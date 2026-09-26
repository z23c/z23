/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Exact host-platform tests for the C23 Commons toolchain descriptor helpers.
 * Darwin additionally exercises the archive normalizer against valid, empty,
 * malformed, and truncated synthetic archives so package receipts never bind
 * a fail-open normalization result. */

#include "test/test_core.h"

#include "platform/toolchain.h"

#include <stdio.h>
#include <string.h>

#if defined(__APPLE__)
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define PT_CHECK(name, expr) do {                                      \
    printf("platform_toolchain: %s... ", (name));                     \
    if (expr) printf("OK\n");                                        \
    else { printf("FAIL\n"); failures++; }                           \
} while (0)

#if defined(__linux__)
/* Records which link tools the descriptor capture asks the driver about,
 * so the tests below can prove the linker byte-identity class is probed —
 * and that a failed probe refuses the capture instead of dropping the
 * class from the preimage. */
struct pt_query_log {
    int ld_queries;
    int collect2_queries;
    int lto1_queries;
    bool fail_ld;
};

static bool pt_query_stub(void *ctx, const char *const argv[],
                          char *out, size_t cap)
{
    struct pt_query_log *log = ctx;
    const char *arg = argv[1];
    static const char prog_prefix[] = "-print-prog-name=";
    static const char file_prefix[] = "-print-file-name=";
    if (strncmp(arg, prog_prefix, sizeof(prog_prefix) - 1) == 0) {
        const char *prog = arg + sizeof(prog_prefix) - 1;
        if (strcmp(prog, "ld") == 0) {
            log->ld_queries++;
            if (log->fail_ld)
                return false;
        } else if (strcmp(prog, "collect2") == 0) {
            log->collect2_queries++;
        } else if (strcmp(prog, "lto1") == 0) {
            log->lto1_queries++;
        }
        int n = snprintf(out, cap, "/stub/%s", prog);
        return n > 0 && (size_t)n < cap;
    }
    if (strncmp(arg, file_prefix, sizeof(file_prefix) - 1) == 0) {
        int n = snprintf(out, cap, "/stub/%s",
                         arg + sizeof(file_prefix) - 1);
        return n > 0 && (size_t)n < cap;
    }
    if (strcmp(arg, "-print-libgcc-file-name") == 0) {
        int n = snprintf(out, cap, "%s", "/stub/libgcc.a");
        return n > 0 && (size_t)n < cap;
    }
    int n = snprintf(out, cap, "%s", "stub-version");
    return n > 0 && (size_t)n < cap;
}

static int pt_link_probe_checks(void)
{
    int failures = 0;
    struct pt_query_log log = {0};
    struct platform_toolchain_descriptor desc;
    PT_CHECK("descriptor capture probes the driver for its linker",
             platform_toolchain_capture_descriptor(
                 pt_query_stub, &log, &desc) &&
             log.ld_queries > 0);
    PT_CHECK("descriptor capture probes the link driver and LTO backend",
             log.collect2_queries > 0 && log.lto1_queries > 0);
    PT_CHECK("descriptor capture reports the full link tool set",
             desc.link_file_count == ZCL_TOOLCHAIN_LINK_COUNT &&
             strcmp(desc.link_files[0], "/stub/collect2") == 0 &&
             strcmp(desc.link_files[1], "/stub/lto1") == 0 &&
             strcmp(desc.link_files[2], "/stub/ld") == 0);
    struct pt_query_log failing = { .fail_ld = true };
    PT_CHECK("descriptor capture refuses an unanswerable linker probe",
             !platform_toolchain_capture_descriptor(
                 pt_query_stub, &failing, &desc));
    return failures;
}
#endif

#if defined(__APPLE__)
static bool pt_write_all(int fd, const void *data, size_t len)
{
    const unsigned char *p = data;
    size_t written = 0;
    while (written < len) {
        ssize_t n = write(fd, p + written, len - written);
        if (n <= 0)
            return false;
        written += (size_t)n;
    }
    return true;
}

static bool pt_rewrite(const char *path, const void *data, size_t len)
{
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0)
        return false;
    bool ok = pt_write_all(fd, data, len);
    if (close(fd) != 0)
        ok = false;
    return ok;
}

static bool pt_read_exact(const char *path, void *data, size_t len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return false;
    unsigned char *p = data;
    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, p + total, len - total);
        if (n <= 0) {
            close(fd);
            return false;
        }
        total += (size_t)n;
    }
    unsigned char extra;
    bool ok = read(fd, &extra, 1) == 0;
    if (close(fd) != 0)
        ok = false;
    return ok;
}

static size_t pt_archive_fixture(unsigned char out[72])
{
    memset(out, ' ', 72);
    memcpy(out, "!<arch>\n", 8);
    memcpy(out + 8, "object.o/", 9);
    memcpy(out + 8 + 16, "1234567890  ", 12);
    memcpy(out + 8 + 28, "501   ", 6);
    memcpy(out + 8 + 34, "20    ", 6);
    memcpy(out + 8 + 40, "100755  ", 8);
    memcpy(out + 8 + 48, "3         ", 10);
    memcpy(out + 8 + 58, "`\n", 2);
    memcpy(out + 68, "abc\n", 4);
    return 72;
}
#endif

int test_platform_toolchain(void)
{
    int failures = 0;
    char target[ZCL_TOOLCHAIN_TARGET_SIZE];
    char arch[128];

    PT_CHECK("canonical target rejects NULL output",
             !platform_toolchain_canonical_target(NULL, sizeof(target)));
    PT_CHECK("canonical target rejects zero capacity",
             !platform_toolchain_canonical_target(target, 0));
    PT_CHECK("canonical target rejects truncation",
             !platform_toolchain_canonical_target(target, 2));
    PT_CHECK("canonical target resolves",
             platform_toolchain_canonical_target(target, sizeof(target)));
    PT_CHECK("architecture flag resolves",
             platform_toolchain_architecture_flag(arch, sizeof(arch)));
    PT_CHECK("architecture flag rejects NULL output",
             !platform_toolchain_architecture_flag(NULL, sizeof(arch)));
    PT_CHECK("Commons architecture flag rejects NULL output",
             !platform_toolchain_commons_architecture_flag(
                 NULL, sizeof(arch)));
    PT_CHECK("Commons deployment flag rejects NULL output",
             !platform_toolchain_commons_deployment_flag(
                 NULL, sizeof(arch)));

#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
    PT_CHECK("Darwin arm64 target is receipt-stable",
             strcmp(target, "darwin-arm64") == 0);
    PT_CHECK("Darwin arm64 native architecture flag is exact",
             strcmp(arch, "-march=armv8-a") == 0);
    PT_CHECK("Darwin arm64 canonical target string is exact",
             strcmp(platform_toolchain_canonical_target_string(),
                    "darwin-arm64") == 0);
    PT_CHECK("Darwin Commons architecture floor is exact",
             platform_toolchain_commons_architecture_flag(
                 arch, sizeof(arch)) && strcmp(arch, "-march=armv8-a") == 0);
    PT_CHECK("Darwin Commons deployment floor is an executable flag",
             platform_toolchain_commons_deployment_flag(
                 arch, sizeof(arch)) &&
             strcmp(arch, "-mmacosx-version-min=14.0") == 0);
    PT_CHECK("Darwin Commons feature macro is exact",
             strcmp(platform_toolchain_commons_feature_macros(),
                    "-D_DARWIN_C_SOURCE") == 0);
    PT_CHECK("Darwin quick flags bind architecture and deployment floor",
             strcmp(platform_toolchain_commons_flags_quick(),
                    "-std=c23 -O1 -march=armv8-a "
                    "-mmacosx-version-min=14.0 -fno-omit-frame-pointer "
                    "-D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE "
                    "-ffile-prefix-map=SOURCE=. -c") == 0);
    PT_CHECK("Darwin standard flags bind architecture and deployment floor",
             strcmp(platform_toolchain_commons_flags_standard_base(),
                    "-std=c23 -O1 -march=armv8-a "
                    "-mmacosx-version-min=14.0 -fno-omit-frame-pointer "
                    "-D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE "
                    "-ffile-prefix-map=SOURCE=. -Wall -Wextra -Werror") == 0);
    PT_CHECK("Darwin sanitizer receipt records ASLR honestly",
             strcmp(platform_toolchain_commons_flags_standard(),
                    "-std=c23 -O1 -march=armv8-a "
                    "-mmacosx-version-min=14.0 -fno-omit-frame-pointer "
                    "-D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE "
                    "-ffile-prefix-map=SOURCE=. -Wall -Wextra -Werror;"
                    "asan,ubsan=clean;sanitizer_pie=off;sanitizer_aslr=on") == 0);
    PT_CHECK("Darwin archive flags omit unsupported GNU D flag",
             strcmp(platform_toolchain_archive_flags(), "rcs") == 0);
    PT_CHECK("Darwin linker omits GNU start group",
             platform_toolchain_linker_group_start() == NULL);
    PT_CHECK("Darwin linker omits GNU end group",
             platform_toolchain_linker_group_end() == NULL);
#elif defined(__linux__)
    PT_CHECK("Linux target is receipt-stable",
             strcmp(target, "linux-x86_64-v3") == 0);
    PT_CHECK("Linux native architecture flag is exact",
             strcmp(arch, "-march=x86-64-v3") == 0);
    PT_CHECK("Linux canonical target string is exact",
             strcmp(platform_toolchain_canonical_target_string(),
                    "linux-x86_64-v3") == 0);
    PT_CHECK("Linux Commons architecture floor is exact",
             platform_toolchain_commons_architecture_flag(
                 arch, sizeof(arch)) &&
             strcmp(arch, "-march=x86-64 -mtune=generic") == 0);
    PT_CHECK("Linux Commons has no separate deployment flag",
             platform_toolchain_commons_deployment_flag(
                 arch, sizeof(arch)) && arch[0] == '\0');
    PT_CHECK("Linux Commons feature macro set is empty",
             platform_toolchain_commons_feature_macros()[0] == '\0');
    PT_CHECK("Linux quick flags preserve their receipt identity",
             strcmp(platform_toolchain_commons_flags_quick(),
                    "-std=c23 -O1 -march=x86-64 -mtune=generic "
                    "-fno-omit-frame-pointer -D_POSIX_C_SOURCE=200809L "
                    "-ffile-prefix-map=SOURCE=. -c") == 0);
    PT_CHECK("Linux standard flags preserve their receipt identity",
             strcmp(platform_toolchain_commons_flags_standard_base(),
                    "-std=c23 -O1 -march=x86-64 -mtune=generic "
                    "-fno-omit-frame-pointer -D_POSIX_C_SOURCE=200809L "
                    "-ffile-prefix-map=SOURCE=. -Wall -Wextra -Werror") == 0);
    PT_CHECK("Linux sanitizer receipt records fixed-ASLR execution",
             strcmp(platform_toolchain_commons_flags_standard(),
                    "-std=c23 -O1 -march=x86-64 -mtune=generic "
                    "-fno-omit-frame-pointer -D_POSIX_C_SOURCE=200809L "
                    "-ffile-prefix-map=SOURCE=. -Wall -Wextra -Werror;"
                    "asan,ubsan=clean;sanitizer_pie=off;sanitizer_aslr=off") == 0);
    PT_CHECK("Linux archive flags request deterministic GNU archives",
             strcmp(platform_toolchain_archive_flags(), "rcsD") == 0);
    PT_CHECK("Linux linker start group is exact",
             strcmp(platform_toolchain_linker_group_start(),
                    "-Wl,--start-group") == 0);
    PT_CHECK("Linux linker end group is exact",
             strcmp(platform_toolchain_linker_group_end(),
                    "-Wl,--end-group") == 0);
#else
    PT_CHECK("other platforms have a nonempty canonical target", target[0] != '\0');
    PT_CHECK("other platforms use portable archive flags",
             strcmp(platform_toolchain_archive_flags(), "rcs") == 0);
#endif

    PT_CHECK("descriptor capture rejects NULL query",
             !platform_toolchain_capture_descriptor(NULL, NULL, NULL));

#if defined(__linux__)
    failures += pt_link_probe_checks();
#endif

#if defined(__APPLE__)
    {
        unsigned char fixture[72];
        unsigned char normalized[72];
        unsigned char normalized_twice[72];
        size_t fixture_len = pt_archive_fixture(fixture);
        (void)mkdir("test-tmp", 0700);
        char path[] = "test-tmp/platform_toolchain_archive_XXXXXX";
        int fd = mkstemp(path);
        bool temp_ok = fd >= 0;
        if (temp_ok) {
            temp_ok = pt_write_all(fd, fixture, fixture_len) && close(fd) == 0;
            fd = -1;
        }
        PT_CHECK("Darwin archive fixture created", temp_ok);
        if (temp_ok) {
            PT_CHECK("Darwin valid archive normalizes",
                     platform_toolchain_normalize_archive(path));
            bool first_read = pt_read_exact(path, normalized,
                                            sizeof(normalized));
            PT_CHECK("Darwin normalized archive remains exact-sized", first_read);
            PT_CHECK("Darwin archive date is normalized",
                     first_read &&
                     memcmp(normalized + 8 + 16, "0           ", 12) == 0);
            PT_CHECK("Darwin archive mode is normalized",
                     first_read &&
                     memcmp(normalized + 8 + 40, "100644  ", 8) == 0);
            PT_CHECK("Darwin archive payload remains byte-identical",
                     first_read && memcmp(normalized + 68, "abc\n", 4) == 0);
            PT_CHECK("Darwin archive normalization is idempotent",
                     platform_toolchain_normalize_archive(path) &&
                     pt_read_exact(path, normalized_twice,
                                   sizeof(normalized_twice)) &&
                     memcmp(normalized, normalized_twice,
                            sizeof(normalized)) == 0);

            unsigned char malformed[72];
            memcpy(malformed, fixture, sizeof(malformed));
            malformed[8 + 58] = '!';
            PT_CHECK("Darwin malformed member header fails closed",
                     pt_rewrite(path, malformed, sizeof(malformed)) &&
                     !platform_toolchain_normalize_archive(path));

            memcpy(malformed, fixture, sizeof(malformed));
            malformed[8 + 48] = 'x';
            PT_CHECK("Darwin non-decimal member size fails closed",
                     pt_rewrite(path, malformed, sizeof(malformed)) &&
                     !platform_toolchain_normalize_archive(path));

            PT_CHECK("Darwin truncated member payload fails closed",
                     pt_rewrite(path, fixture, sizeof(fixture) - 1) &&
                     !platform_toolchain_normalize_archive(path));
            PT_CHECK("Darwin empty archive is valid",
                     pt_rewrite(path, fixture, 8) &&
                     platform_toolchain_normalize_archive(path));
            PT_CHECK("Darwin bad archive magic fails closed",
                     pt_rewrite(path, "!<bad>\nX", 8) &&
                     !platform_toolchain_normalize_archive(path));

            PT_CHECK("Darwin archive object fixture rewrites",
                     pt_rewrite(path, "object", 6));
            struct timespec times[2] = {{123, 0}, {456, 0}};
            PT_CHECK("Darwin archive object fixture gets nonzero times",
                     utimensat(AT_FDCWD, path, times, 0) == 0);
            const char *objects[] = {path};
            PT_CHECK("Darwin archive object times normalize",
                     platform_toolchain_prepare_archive_objects(objects, 1));
            struct stat st;
            PT_CHECK("Darwin archive object times become epoch zero",
                     stat(path, &st) == 0 &&
                     st.st_atimespec.tv_sec == 0 &&
                     st.st_mtimespec.tv_sec == 0);
            const char *bad_objects[] = {NULL};
            PT_CHECK("Darwin NULL archive object fails closed",
                     !platform_toolchain_prepare_archive_objects(
                         bad_objects, 1));
            PT_CHECK("Darwin empty archive object set is valid",
                     platform_toolchain_prepare_archive_objects(NULL, 0));
            unlink(path);
        }
        if (fd >= 0)
            close(fd);
    }
#endif

    if (failures == 0)
        printf("=== platform_toolchain tests: ALL PASS ===\n");
    else
        printf("=== platform_toolchain tests: %d FAILURE(S) ===\n", failures);
    return failures;
}
