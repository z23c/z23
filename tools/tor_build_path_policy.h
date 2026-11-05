/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: name and validate the Tor archive build-path provenance policy. */
#ifndef ZCL_TOR_BUILD_PATH_POLICY_H
#define ZCL_TOR_BUILD_PATH_POLICY_H

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "platform/file_sync.h"
#include "platform/path_replace.h"

#define TOR_BUILD_PATH_POLICY "root-map-v1"
#define TOR_BUILD_LOGICAL_ROOT "/zclassic23"
#define TOR_PATH_BLOCK_BEGIN "# z23 tor build path begin\n"
#define TOR_PATH_BLOCK_END "# z23 tor build path end\n"

/* config.status argv is decoded by the existing literal xargs route. Check
 * presence as NUL-separated data, never shell source or a substring in a value. */
static int tor_build_path_cflags_absent(FILE *in)
{
    char argument[8192]; size_t used = 0;
    int c;
    while ((c = fgetc(in)) != EOF) {
        if (c == 0) {
            argument[used] = '\0';
            if (!strncmp(argument, "CFLAGS=", 7)) return 0;
            used = 0;
        } else {
            if (used >= sizeof(argument) - 1u) return 0;
            argument[used++] = (char)c;
        }
    }
    return !ferror(in) && used == 0;
}

/* Missing, duplicate and unsupported declarations remain distinct from a
 * producer-attested current policy. No archive bytes are normalized here. */
static inline void tor_build_path_policy_parse(int *status, const char *value)
{
    *status = *status == 0 && strcmp(value, TOR_BUILD_PATH_POLICY) == 0 ? 1 : -1;
}

static int tor_build_path_policy_check(int status)
{
    if (status == 1) return 1;
    puts("tor-provenance: build_path_policy MISMATCH missing or unsupported; clean rebuild required");
    return 0;
}

/* These bytes become Make syntax and then compiler argv. Refuse characters
 * requiring either language's quoting rather than evaluating a path as code. */
static int tor_build_path_root_safe(const char *root)
{
    if (!root || root[0] != '/' || strlen(root) >= 4096) return 0;
    for (const unsigned char *p = (const unsigned char *)root; *p; p++) {
        int alpha = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z');
        int digit = *p >= '0' && *p <= '9';
        if (!alpha && !digit && !strchr("/._:-", *p)) return 0;
    }
    return 1;
}

static int tor_build_path_name(char out[8192], const char *dir, const char *leaf)
{
    int n = snprintf(out, 8192, "%s/%s", dir, leaf);
    return n > 0 && n < 8192;
}

static int tor_build_path_block(char out[8192], const char *root)
{
    if (!tor_build_path_root_safe(root)) return 0;
    int n = snprintf(out, 8192, TOR_PATH_BLOCK_BEGIN
        "# build_path_policy=" TOR_BUILD_PATH_POLICY "\n"
        "override CFLAGS += -ffile-prefix-map=%s=" TOR_BUILD_LOGICAL_ROOT
        " -fdebug-prefix-map=%s=" TOR_BUILD_LOGICAL_ROOT "\n"
        TOR_PATH_BLOCK_END, root, root);
    return n > 0 && n < 8192;
}

/* Read exactly one owned four-line block, never arbitrary Make expressions. */
static int tor_build_path_existing_valid(const char *block)
{
    static const char prefix[] = TOR_PATH_BLOCK_BEGIN
        "# build_path_policy=" TOR_BUILD_PATH_POLICY "\n"
        "override CFLAGS += -ffile-prefix-map=";
    if (strncmp(block, prefix, sizeof(prefix) - 1u)) return 0;
    const char *start = block + sizeof(prefix) - 1u, *end = strchr(start, '=');
    char root[4096], expected[8192];
    if (!end || end == start || (size_t)(end - start) >= sizeof(root)) return 0;
    memcpy(root, start, (size_t)(end - start)); root[end - start] = '\0';
    return tor_build_path_block(expected, root) && !strcmp(block, expected);
}

static int tor_build_path_read_block(FILE *in, char block[8192])
{
    size_t used = strlen(TOR_PATH_BLOCK_BEGIN);
    memcpy(block, TOR_PATH_BLOCK_BEGIN, used + 1u);
    for (int i = 0; i < 3; i++) {
        if (!fgets(block + used, (int)(8192u - used), in)) return 0;
        size_t n = strlen(block + used);
        if (!n || block[used + n - 1u] != '\n') return 0;
        used += n;
        if (used >= 8191u) return 0;
    }
    size_t end = strlen(TOR_PATH_BLOCK_END);
    return used >= end && !strcmp(block + used - end, TOR_PATH_BLOCK_END) &&
        tor_build_path_existing_valid(block);
}

/* In-place generated-Makefile policy is separate from configure's selected
 * CFLAGS. A terminal override appends to defaults, hardened flags, explicitly
 * empty CFLAGS and later make-command-line CFLAGS without replacing them. */
static int tor_build_path_scan(FILE *in, FILE *out, const char *wanted, int *same)
{
    char line[8192], block[8192];
    int seen = 0;
    *same = 0;
    while (fgets(line, sizeof(line), in)) {
        size_t n = strlen(line);
        if (n && line[n - 1u] != '\n' && !feof(in)) return 0;
        if (!strcmp(line, TOR_PATH_BLOCK_BEGIN)) {
            if (seen++ || !tor_build_path_read_block(in, block)) return 0;
            *same = !strcmp(block, wanted);
        } else {
            if (strstr(line, "# z23 tor build path")) return 0;
            /* A later Make expression may undo the map. Installation keeps
             * it, then moves our block last; checking must refuse it. */
            if (seen && strspn(line, " \t\r\n") != n) *same = 0;
            if (out && fputs(line, out) == EOF) return 0;
        }
    }
    return !ferror(in);
}

static int tor_build_path_matches(const char *dir, const char *root)
{
    char path[8192], block[8192];
    if (!tor_build_path_name(path, dir, "Makefile") || !tor_build_path_block(block, root)) return 0;
    FILE *in = fopen(path, "rb");
    if (!in) return 0;
    int same = 0;
    int ok = tor_build_path_scan(in, NULL, block, &same);
    if (fclose(in) != 0) ok = 0;
    return ok && same;
}

static int tor_build_path_publish(FILE *in, FILE *out, const char *block)
{
    int same = 0;
    if (!tor_build_path_scan(in, out, block, &same)) return 0;
    if (fputs("\n", out) == EOF || fputs(block, out) == EOF) return 0;
    return fflush(out) == 0 && platform_file_sync(fileno(out)) == 0;
}

static int tor_build_path_install(const char *dir, const char *root)
{
    char path[8192], tmp[8192], block[8192];
    if (!tor_build_path_name(path, dir, "Makefile") || !tor_build_path_block(block, root)) return 1;
    if (tor_build_path_matches(dir, root)) return 0;
    int n = snprintf(tmp, sizeof(tmp), "%s.z23-path.%ld", path, (long)getpid());
    if (n <= 0 || (size_t)n >= sizeof(tmp)) return 1;
    FILE *in = fopen(path, "rb");
    FILE *out = in ? fopen(tmp, "wbx") : NULL;
    if (!out) { if (in) fclose(in); return 1; }
    int ok = tor_build_path_publish(in, out, block);
    if (fclose(in) != 0) ok = 0;
    if (fclose(out) != 0) ok = 0;
    if (ok) ok = platform_path_replace(tmp, path) == 0;
    if (!ok) unlink(tmp);
    return ok ? 0 : 1;
}

/* Producer write requires an actual managed recipe rooted above this Tor
 * tree. Consumer check needs only the attested policy plus exact archive
 * hashes: a copied immutable artifact need not carry the donor Makefile. */
static int tor_build_path_configured(const char *dir)
{
    char path[8192], line[8192], root[4096];
    if (!tor_build_path_name(path, dir, "Makefile")) return 0;
    FILE *in = fopen(path, "rb");
    if (!in) return 0;
    static const char prefix[] = "override CFLAGS += -ffile-prefix-map=";
    int found = 0;
    while (fgets(line, sizeof(line), in)) {
        if (strncmp(line, prefix, sizeof(prefix) - 1u)) continue;
        const char *start = line + sizeof(prefix) - 1u;
        const char *end = strchr(start, '=');
        if (!end || end == start || (size_t)(end - start) >= sizeof(root)) continue;
        memcpy(root, start, (size_t)(end - start)); root[end - start] = '\0';
        size_t n = strlen(root);
        if (!strncmp(dir, root, n) && (dir[n] == '/' || dir[n] == '\0')) found++;
    }
    int ok = !ferror(in) && found == 1;
    if (fclose(in) != 0) ok = 0;
    return ok && tor_build_path_matches(dir, root);
}

static int tor_build_path_terminal_test(const char *dir)
{
    char path[8192];
    if (!tor_build_path_name(path, dir, "Makefile")) return 1;
    FILE *out = fopen(path, "ab");
    if (!out) return 1;
    int ok = fputs("override CFLAGS = -O0\n", out) >= 0;
    if (fclose(out) != 0) ok = 0;
    if (!ok || tor_build_path_matches(dir, dir) || tor_build_path_configured(dir)) return 1;
    return tor_build_path_install(dir, dir) || !tor_build_path_matches(dir, dir);
}

static int tor_build_path_duplicate_test(const char *dir)
{
    char path[8192], block[8192];
    if (!tor_build_path_name(path, dir, "Makefile") || !tor_build_path_block(block, dir)) return 1;
    FILE *out = fopen(path, "ab");
    if (!out) return 1;
    int ok = fputs(block, out) >= 0;
    if (fclose(out) != 0) ok = 0;
    return !ok || tor_build_path_matches(dir, dir) || !tor_build_path_install(dir, dir);
}

static int tor_build_path_fixture_write(const char *dir)
{
    char path[8192];
    if (!tor_build_path_name(path, dir, "Makefile")) return 1;
    FILE *out = fopen(path, "wb");
    if (!out) return 1;
    int ok = fputs("CFLAGS = -g -O2\n", out) >= 0;
    if (fclose(out) != 0) ok = 0;
    return ok ? tor_build_path_install(dir, dir) : 1;
}

static int tor_build_path_fixture(const char *dir)
{
    if (tor_build_path_fixture_write(dir) || tor_build_path_terminal_test(dir) ||
        tor_build_path_duplicate_test(dir)) return 1;
    return tor_build_path_fixture_write(dir);
}

static int tor_build_path_cflags_fixture(void)
{
    static const char absent[] = "--disable-x\0CPPFLAGS=-DCFLAGS=7\0";
    static const char empty[] = "--disable-x\0CFLAGS=\0";
    static const char custom[] = "CFLAGS=-O0 -g\0";
    const struct { const char *data; size_t size; int wanted; } cases[] = {
        {absent, sizeof(absent) - 1u, 1}, {empty, sizeof(empty) - 1u, 0},
        {custom, sizeof(custom) - 1u, 0}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        FILE *in = tmpfile();
        if (!in) return 1;
        int ok = fwrite(cases[i].data, 1, cases[i].size, in) == cases[i].size;
        rewind(in);
        if (tor_build_path_cflags_absent(in) != cases[i].wanted) ok = 0;
        if (fclose(in) != 0) ok = 0;
        if (!ok) return 1;
    }
    return 0;
}

/* Existing tool modes retain their dispatcher; these bounded policy modes
 * neither configure Tor nor attest archive contents. -1 means not handled. */
static int tor_build_path_dispatch(int argc, char **argv)
{
    if (!strcmp(argv[1], "check-configure-cflags-absent")) {
        if (argc == 2) return !tor_build_path_cflags_absent(stdin);
    } else if (!strcmp(argv[1], "map-build-path") || !strcmp(argv[1], "check-build-path")) {
        if (argc == 4) return argv[1][0] == 'm' ? tor_build_path_install(argv[2], argv[3]) :
            !tor_build_path_matches(argv[2], argv[3]);
    } else return -1;
    fputs("tor-provenance: invalid build-path command arguments\n", stderr);
    return 2;
}

static int tor_build_path_archive_after_recipe(const char *dir, const char *leaf)
{
    char recipe[8192], archive[8192];
    struct stat r, a;
    if (!tor_build_path_name(recipe, dir, "Makefile") ||
        !tor_build_path_name(archive, dir, leaf) ||
        stat(recipe, &r) != 0 || stat(archive, &a) != 0) return 0;
    if (!S_ISREG(r.st_mode) || !S_ISREG(a.st_mode)) return 0;
#if defined(__APPLE__)
    return a.st_mtimespec.tv_sec > r.st_mtimespec.tv_sec ||
        (a.st_mtimespec.tv_sec == r.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec >= r.st_mtimespec.tv_nsec);
#elif defined(_WIN32)
    return a.st_mtime >= r.st_mtime;
#else
    return a.st_mtim.tv_sec > r.st_mtim.tv_sec ||
        (a.st_mtim.tv_sec == r.st_mtim.tv_sec && a.st_mtim.tv_nsec >= r.st_mtim.tv_nsec);
#endif
}

#endif
