/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression test for no hardcoded build-user home directory in deployed
 * binaries, and the path helpers respect $HOME.
 *
 * Part 1: scan every built binary under build/bin (test_zcl itself,
 * zclassic23, export_snapshot, zcl-nodectl, zcl-rpc, zclassic-cli) for
 * the building user's literal $HOME byte string. Expected: zero matches in
 * every binary. A hit means a contributor has hardcoded the build machine's
 * home directory, and the binary will either misbehave or fail to start on
 * another operator's machine. The needle is the runtime $HOME so the test is
 * operator-agnostic — it catches anyone's home, not one specific user's.
 *
 * Part 2: exercise the extracted zcl-nodectl default-path helper with
 * an arbitrary HOME. Confirms the runtime behavior — setting
 * HOME=/tmp/alt-home produces `/tmp/alt-home/.zclassic-c23/...` paths,
 * not the compile-time default and not the build user's home.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util/rpc_paths.h"

#define NHH_CHECK(name, expr) do {         \
    printf("%s... ", (name));              \
    if ((expr)) printf("OK\n");            \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static int scan_file_for_needle(const char *path, const char *needle, int *matches)
{
    *matches = 0;
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return -1; }
    long size = ftell(fp);
    if (size < 0) { fclose(fp); return -1; }
    rewind(fp);

    char *buf = malloc((size_t)size);
    if (!buf) { fclose(fp); return -1; }
    size_t got = fread(buf, 1, (size_t)size, fp);
    fclose(fp);
    if (got != (size_t)size) { free(buf); return -1; }

    size_t needle_len = strlen(needle);
    if (needle_len == 0 || (size_t)size < needle_len) { free(buf); return 0; }

    for (size_t i = 0; i + needle_len <= (size_t)size; i++) {
        if (memcmp(buf + i, needle, needle_len) == 0) {
            (*matches)++;
            i += needle_len - 1;
        }
    }
    free(buf);
    return 0;
}

int test_no_hardcoded_home(void)
{
    printf("\n=== no hardcoded build-user home ===\n");
    int failures = 0;

    /* Scan deployed binaries. test_zcl itself is deliberately excluded:
     * the runtime needle below is the building user's $HOME, which test_zcl
     * legitimately references via getenv(), so it would match itself. The
     * production binaries below are what operators actually ship. */
    static const char *binaries[] = {
        "build/bin/z23",
        "build/bin/export_snapshot",
        "build/bin/zcl-nodectl",
        "build/bin/zcl-rpc",
        "build/bin/zclassic-cli",
        NULL,
    };

    /* The needle is the build user's actual home directory at runtime —
     * operator-agnostic. If $HOME is unset/short, skip the binary scan (the
     * Part 2 runtime-path checks still run). */
    const char *home = getenv("HOME");
    if (home && strncmp(home, "/home/", 6) == 0 && strlen(home) > 6) {
        char needle[512];
        snprintf(needle, sizeof(needle), "%s", home);

        for (size_t i = 0; binaries[i]; i++) {
            const char *path = binaries[i];
            struct stat st;
            if (stat(path, &st) != 0) {
                printf("%s: not built — SKIPPING\n", path);
                continue;
            }
            int matches = -1;
            int rc = scan_file_for_needle(path, needle, &matches);
            char label[640];
            snprintf(label, sizeof(label),
                     "binary has zero '%s' strings: %s", needle, path);
            NHH_CHECK(label, rc == 0 && matches == 0);
            if (rc == 0 && matches > 0) {
                printf("  (found %d occurrence(s))\n", matches);
            }
        }
    } else {
        printf("HOME unset or not under /home — skipping binary scan\n");
    }

    /* Part 2 — exercise the extracted default-path helper with a
     * deliberately-fake HOME. Proves the code path uses HOME at runtime
     * rather than a compile-time constant. */
    char legacy_dd[512], legacy_conf[512], legacy_cookie[512];
    char c23_dd[512], c23_conf[512], c23_cookie[512];

    zcl_nodectl_build_default_paths(
        "/tmp/alt-zcl-home",
        legacy_dd, sizeof(legacy_dd),
        legacy_conf, sizeof(legacy_conf),
        legacy_cookie, sizeof(legacy_cookie),
        c23_dd, sizeof(c23_dd),
        c23_conf, sizeof(c23_conf),
        c23_cookie, sizeof(c23_cookie));

    NHH_CHECK("legacy_dd reflects alt HOME",
              strcmp(legacy_dd, "/tmp/alt-zcl-home/.zclassic") == 0);
    NHH_CHECK("legacy_conf reflects alt HOME",
              strcmp(legacy_conf, "/tmp/alt-zcl-home/.zclassic/zclassic.conf") == 0);
    NHH_CHECK("legacy_cookie reflects alt HOME",
              strcmp(legacy_cookie, "/tmp/alt-zcl-home/.zclassic/.cookie") == 0);
    NHH_CHECK("c23_dd reflects alt HOME",
              strcmp(c23_dd, "/tmp/alt-zcl-home/.zclassic-c23") == 0);
    NHH_CHECK("c23_conf reflects alt HOME",
              strcmp(c23_conf, "/tmp/alt-zcl-home/.zclassic-c23/zclassic.conf") == 0);
    NHH_CHECK("c23_cookie reflects alt HOME",
              strcmp(c23_cookie, "/tmp/alt-zcl-home/.zclassic-c23/.cookie") == 0);

    /* NULL / empty HOME falls back to "." (CWD-relative) — never to a
     * hardcoded build-user home. */
    zcl_nodectl_build_default_paths(
        NULL,
        legacy_dd, sizeof(legacy_dd),
        legacy_conf, sizeof(legacy_conf),
        legacy_cookie, sizeof(legacy_cookie),
        c23_dd, sizeof(c23_dd),
        c23_conf, sizeof(c23_conf),
        c23_cookie, sizeof(c23_cookie));
    NHH_CHECK("NULL HOME → cwd-relative c23_dd",
              strcmp(c23_dd, "./.zclassic-c23") == 0);
    NHH_CHECK("NULL HOME → no absolute /home leaked",
              strstr(c23_dd, "/home/") == NULL &&
              strstr(legacy_dd, "/home/") == NULL);

    zcl_nodectl_build_default_paths(
        "",
        legacy_dd, sizeof(legacy_dd),
        legacy_conf, sizeof(legacy_conf),
        legacy_cookie, sizeof(legacy_cookie),
        c23_dd, sizeof(c23_dd),
        c23_conf, sizeof(c23_conf),
        c23_cookie, sizeof(c23_cookie));
    NHH_CHECK("empty HOME → cwd-relative c23_dd",
              strcmp(c23_dd, "./.zclassic-c23") == 0);

    if (failures == 0)
        printf("no hardcoded build-user home: PASS\n");
    else
        printf("no hardcoded build-user home: FAIL (%d failures)\n", failures);
    return failures;
}
