/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Bind retained installer source to the current executable and manifest. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE 1
#endif
#include "command/app_installed_source_resolve.h"
#include "command/native_package_artifact.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/sha256.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "util/path_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#if defined(__linux__) || defined(__APPLE__)
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#define ISR_PATH 4096u
#define ISR_MANIFEST 2048u
#define ISR_MIB (1024u * 1024u)
enum { ISR_CARD, ISR_RECORD, ISR_PROJECTION, ISR_PACKAGE, ISR_RECIPE,
    ISR_BUNDLE, ISR_NODE, ISR_ACME, ISR_VERIFY, ISR_GAME,
    ISR_NODE_ALIAS, ISR_ACME_ALIAS, ISR_VERIFY_ALIAS, ISR_BASE_ROWS,
    ISR_DESKTOP_RECEIVE = ISR_BASE_ROWS, ISR_DESKTOP_ICON, ISR_DESKTOP_MIME,
    ISR_DESKTOP_GAME, ISR_DESKTOP_END, ISR_KIT_DESCRIPTOR = ISR_DESKTOP_END,
    ISR_KIT_BUNDLE, ISR_ROWS };
static const char *const isr_names[ISR_ROWS] = {
    "AGENT_CARD.md", "app-build.wire", "installed-source.json", // error-doc-ref-ok: generated installed release assets, not checkout documents
    "manifest.wire", "recipe.wire", "source.bundle", "z23", "z23-acme",
    "z23-package-verify", "z23-skycombat", "zclassic23", "zclassic23-acme",
    "zclassic23-package-verify", "org.zclassic.ZClassic23.desktop",
    "org.zclassic.ZClassic23.svg", "org.zclassic.ZClassic23.xml",
    "org.zclassic.SkyCombat.desktop", "app-toolchain.json", "app-toolchain.bundle"
};
static const size_t isr_limits[ISR_ROWS] = {
    65536, 240, 4096, ISR_MIB, 256u * 1024u, 64u * ISR_MIB,
    64u * ISR_MIB, 32u * ISR_MIB, 128u * ISR_MIB, 64u * ISR_MIB,
    64u * ISR_MIB, 32u * ISR_MIB, 128u * ISR_MIB,
    65536, 65536, 65536, 65536, 4096, 64u * ISR_MIB
};
struct isr_manifest { char digest[ISR_ROWS][65]; };
struct isr_layout {
    char exe[ISR_PATH], dir[ISR_PATH], generation[65];
    bool mac;
};
static bool isr_lower_hex(const char *s)
{
    uint8_t decoded[32];
    return zcl_hex_decode_lower(s, decoded, sizeof(decoded));
}
static bool isr_trusted(const struct stat *st)
{
    return (st->st_uid == 0 || st->st_uid == geteuid()) && !(st->st_mode & 022);
}
static bool isr_dir_ok(int fd)
{
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) && isr_trusted(&st);
}
/* Walk from root, retaining each parent while opening its child. No realpath
 * inference, writable sticky exception, or owner/mode repair. */
static int isr_directory(const char *path)
{
    if (path[0] != '/' || strlen(path) >= ISR_PATH) return -1;
    char copy[ISR_PATH];
    memcpy(copy, path + 1, strlen(path));
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    char *at = copy;
    while (*at && isr_dir_ok(fd)) {
        char *slash = strchr(at, '/');
        if (slash) *slash = 0;
        if (!*at || !strcmp(at, ".") || !strcmp(at, "..")) break;
        int next = openat(fd, at, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        close(fd); fd = next;
        if (fd < 0) return -1;
        if (!slash) return isr_dir_ok(fd) ? fd : (close(fd), -1);
        at = slash + 1;
    }
    close(fd);
    return -1;
}
static bool isr_exe_path(char *out, size_t cap)
{
    if (!os_proc_exe_path(out, cap)) return false;
#if defined(__APPLE__)
    /* os_proc_exe_path permits a raw _NSGetExecutablePath fallback when
     * realpath fails. This resolver requires canonical generation grammar.
     * Ownership/no-link checks of the resolved ancestors still follow. */
    char resolved[PATH_MAX];
    if (!realpath(out, resolved)) return false;
    size_t n = strlen(resolved);
    if (n >= cap) return false;
    memcpy(out, resolved, n + 1);
#endif
    return true;
}
#if defined(__linux__)
static bool isr_game_link(const char *prefix)
{
    static const char target[] = "../share/z23/apps/skycombat/z23-skycombat";
    char bin[ISR_PATH], actual[sizeof(target)];
    if (!zcl_path_join(bin, sizeof(bin), prefix, "bin")) return false;
    int fd = isr_directory(bin);
    if (fd < 0) return false;
    ssize_t n = readlinkat(fd, "z23-skycombat", actual, sizeof(actual));
    bool ok = n == (ssize_t)(sizeof(target) - 1);
    if (ok) ok = !memcmp(actual, target, sizeof(target) - 1);
    if (close(fd) != 0) ok = false;
    return ok;
}
#endif
static bool isr_layout(struct isr_layout *l)
{
    memset(l, 0, sizeof(*l));
    if (!isr_exe_path(l->exe, sizeof(l->exe))) return false;
    size_t n = strlen(l->exe);
#if defined(__APPLE__)
    l->mac = true;
    if (n < 70 || strcmp(l->exe + n - 4, "/z23")) return false;
    memcpy(l->dir, l->exe, n - 4);
    char *component = strrchr(l->dir, '/');
    if (!component || !isr_lower_hex(component + 1)) return false;
    memcpy(l->generation, component + 1, 65);
    size_t prefix = (size_t)(component - l->dir);
    const char suffix[] = "/lib/z23/generations";
    return prefix > sizeof(suffix) - 1 &&
        !memcmp(l->dir + prefix - (sizeof(suffix)-1), suffix, sizeof(suffix)-1);
#else
    if (n <= 8 || strcmp(l->exe + n - 8, "/bin/z23")) return false;
    char parent[ISR_PATH];
    memcpy(parent, l->exe, n - 8); parent[n-8] = 0;
    if (!isr_game_link(parent)) return false;
    if (!zcl_path_join(l->dir, sizeof(l->dir), parent, "share/z23/apps")) return false;
    int fd = isr_directory(l->dir);
    if (fd < 0) return false;
    ssize_t count = readlinkat(fd, "skycombat", l->generation, sizeof(l->generation));
    close(fd);
    if (count != 64) return false;
    l->generation[64] = 0;
    if (!isr_lower_hex(l->generation)) return false;
    memcpy(parent, l->dir, strlen(l->dir) + 1);
    return zcl_path_join(l->dir, sizeof(l->dir), parent, l->generation);
#endif
}
static bool isr_readable(int fd, size_t maximum,
    struct platform_positioned_file_snapshot *before)
{
    struct stat st;
    struct platform_positioned_file file = { .native = (uintptr_t)fd };
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || !isr_trusted(&st)) return false;
    return platform_positioned_file_snapshot(&file, before) &&
        before->size != 0 && before->size <= maximum;
}
static bool isr_stream(int fd, size_t maximum, char hex[65],
    void *small, size_t small_cap, size_t *length)
{
    *length = 0;
    struct platform_positioned_file file = { .native = (uintptr_t)fd };
    struct platform_positioned_file_snapshot before, after;
    if (!isr_readable(fd, maximum, &before)) return false;
    if (small && before.size > small_cap) return false;
    struct sha256_ctx hash; sha256_init(&hash);
    uint8_t block[16384]; uint64_t at = 0;
    while (at < before.size) {
        size_t want = (size_t)(before.size - at);
        if (want > sizeof(block)) want = sizeof(block);
        int64_t got = platform_positioned_file_read(&file, block, want, at);
        if (got <= 0 || (uint64_t)got > want) return false;
        sha256_write(&hash, block, (size_t)got);
        if (small) memcpy((uint8_t *)small + at, block, (size_t)got);
        at += (uint64_t)got;
    }
    if (platform_positioned_file_read(&file, block, 1, at) != 0) return false;
    if (!platform_positioned_file_snapshot(&file, &after) ||
        !platform_positioned_file_snapshot_equal(&before, &after)) return false;
    uint8_t digest[32]; sha256_finalize(&hash, digest); zcl_hex_encode(digest, sizeof(digest), hex);
    *length = (size_t)at;
    return true;
}
static bool isr_member(int dir, const char *name, size_t maximum,
    char hex[65], void *small, size_t cap, size_t *length)
{
    *length = 0;
    int fd = openat(dir, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return false;
    bool ok = isr_stream(fd, maximum, hex, small, cap, length);
    if (close(fd) != 0) ok = false;
    return ok;
}
static int isr_row(const char *name)
{
    for (int i = 0; i < ISR_ROWS; ++i)
        if (!strcmp(name, isr_names[i])) return i;
    return -1;
}
static bool isr_shape(const struct isr_manifest *m, bool mac)
{
    /* Count alone is insufficient: four optional rows cannot replace base rows. */
    for (int row = 0; row < ISR_BASE_ROWS; ++row)
        if (!m->digest[row][0]) return false;
    unsigned desktop = 0;
    for (int row = ISR_BASE_ROWS; row < ISR_DESKTOP_END; ++row)
        if (m->digest[row][0]) ++desktop;
    unsigned kit = (m->digest[ISR_KIT_DESCRIPTOR][0] != 0) +
        (m->digest[ISR_KIT_BUNDLE][0] != 0);
    if (kit && (kit != 2 || mac || desktop != ISR_DESKTOP_END - ISR_BASE_ROWS)) return false;
    return desktop == 0 || (!mac && desktop == ISR_DESKTOP_END - ISR_BASE_ROWS);
}
static bool isr_parse(char *bytes, size_t length, struct isr_manifest *m, bool mac)
{
    memset(m, 0, sizeof(*m));
    if (memchr(bytes, 0, length)) return false;
    char *at = bytes, *end = bytes + length;
    while (at < end) {
        char *nl = memchr(at, '\n', (size_t)(end-at));
        if (!nl || nl-at < 67 || at[64] != ' ' || at[65] != ' ') return false;
        *nl = 0; at[64] = 0;
        int row = isr_row(at+66);
        if (row < 0 || m->digest[row][0] || !isr_lower_hex(at)) return false;
        memcpy(m->digest[row], at, 65); at = nl+1;
    }
    return isr_shape(m, mac) &&
        !strcmp(m->digest[ISR_NODE], m->digest[ISR_NODE_ALIAS]) &&
        !strcmp(m->digest[ISR_ACME], m->digest[ISR_ACME_ALIAS]) &&
        !strcmp(m->digest[ISR_VERIFY], m->digest[ISR_VERIFY_ALIAS]);
}
static bool isr_manifest(int dir, const struct isr_layout *l,
    struct isr_manifest *m, char manifest_hash[65])
{
    char bytes[ISR_MANIFEST + 1]; size_t length = 0;
    if (!isr_member(dir, "SHA256SUMS", ISR_MANIFEST, manifest_hash,
            bytes, ISR_MANIFEST, &length)) return false;
    bytes[length] = 0;
    if (!l->mac && strcmp(manifest_hash, l->generation)) return false;
    if (!isr_parse(bytes, length, m, l->mac)) return false;
    return !l->mac || !strcmp(m->digest[ISR_NODE], l->generation);
}
static bool isr_same_self(int named, FILE *self, const struct isr_manifest *m)
{
    if (!self) return false;
    struct stat a, b;
    if (fstat(named, &a) != 0 || fstat(fileno(self), &b) != 0) return false;
    if (a.st_dev != b.st_dev || a.st_ino != b.st_ino) return false;
    char hex[65]; size_t length;
    return isr_stream(fileno(self), isr_limits[ISR_NODE], hex, NULL, 0, &length) &&
        !strcmp(hex, m->digest[ISR_NODE]);
}
static bool isr_self(const struct isr_layout *l, const struct isr_manifest *m)
{
    char parent[ISR_PATH]; memcpy(parent, l->exe, strlen(l->exe)+1);
    char *slash = strrchr(parent, '/');
    if (!slash) return false;
    *slash = 0;
    int dir = isr_directory(parent);
    if (dir < 0) return false;
    int named = openat(dir, "z23", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    close(dir);
    if (named < 0) return false;
    FILE *self = os_proc_open_self_exe();
    bool ok = isr_same_self(named, self, m);
    if (self && fclose(self) != 0) ok = false;
    if (close(named) != 0) ok = false;
    return ok;
}
static bool isr_desktop_assets(int dir, const struct isr_manifest *m)
{
    if (!m->digest[ISR_DESKTOP_RECEIVE][0]) return true;
    for (int row = ISR_BASE_ROWS; row < ISR_DESKTOP_END; ++row) {
        char hex[65]; size_t length;
        if (!isr_member(dir, isr_names[row], isr_limits[row], hex, NULL, 0, &length) ||
            strcmp(hex, m->digest[row])) return false;
    }
    return true;
}
#if defined(ZCL_TESTING)
/* Component seam only: never supplies a substitute executing image/ancestor
 * to the production resolver, and never returns admitted source authority. */
bool zcl_test_installed_desktop_manifest(int dir, const char *wire, size_t length, bool mac);
bool zcl_test_installed_desktop_manifest(int dir, const char *wire, size_t length, bool mac)
{
    if (!wire || length > ISR_MANIFEST) return false;
    char bytes[ISR_MANIFEST + 1]; struct isr_manifest manifest;
    memcpy(bytes, wire, length); bytes[length] = 0;
    return isr_parse(bytes, length, &manifest, mac) && isr_desktop_assets(dir, &manifest);
}
#endif
static bool isr_assets(int dir, const struct isr_manifest *m, char pin[65])
{
    uint8_t projection[4096]; size_t length = 0;
    char hex[65];
    for (int row = ISR_RECORD; row <= ISR_BUNDLE; ++row) {
        void *small = row == ISR_PROJECTION ? projection : NULL;
        if (!isr_member(dir, isr_names[row], isr_limits[row], hex,
                small, sizeof(projection), &length)) return false;
        if (strcmp(hex, m->digest[row])) return false;
        if (row == ISR_PROJECTION) {
            uint8_t digest[32];
            zcl_native_package_artifact_digest(digest, projection, length);
            zcl_hex_encode(digest, sizeof(digest), pin);
        }
    }
    return isr_member(dir, isr_names[ISR_GAME], isr_limits[ISR_GAME],
        hex, NULL, 0, &length) && !strcmp(hex, m->digest[ISR_GAME]) && isr_desktop_assets(dir, m);
}
static bool isr_retained(const struct app_installed_source *out,
    const struct isr_manifest *m)
{
    const struct app_installed_source_bytes *const bytes[] = {
        &out->record, &out->projection, &out->manifest, &out->recipe, &out->bundle
    };
    for (size_t i = 0; i < sizeof(bytes)/sizeof(bytes[0]); ++i) {
        struct sha256_ctx hash; uint8_t digest[32]; char hex[65];
        sha256_init(&hash); sha256_write(&hash, bytes[i]->bytes, bytes[i]->length);
        sha256_finalize(&hash, digest); zcl_hex_encode(digest, sizeof(digest), hex);
        if (strcmp(hex, m->digest[ISR_RECORD+i])) return false;
    }
    return !strcmp(out->app, "skycombat");
}
static bool isr_binding_matches(int dir, const struct isr_layout *l, const char *mh)
{
    struct isr_layout again; struct isr_manifest final; char final_hash[65];
    return isr_layout(&again) && !strcmp(l->exe, again.exe) && !strcmp(l->dir, again.dir) &&
        isr_manifest(dir, l, &final, final_hash) && !strcmp(mh, final_hash);
}
static bool isr_recheck(int dir, const struct isr_layout *l,
    const struct isr_manifest *manifest, const char *mh, const char *pin)
{
    /* Recheck selector, manifest and member bytes after loader pathname reads;
     * authorized whole-install replacement remains outside this threat model. */
    char final_pin[65];
    if (!isr_binding_matches(dir, l, mh)) return false;
    if (!isr_assets(dir, manifest, final_pin) || strcmp(pin, final_pin)) return false;
    return isr_self(l, manifest);
}
static bool isr_resolve(struct app_installed_source *out, char *why, size_t cap)
{
    struct isr_layout l;
    if (!isr_layout(&l)) return false;
    int dir = isr_directory(l.dir);
    if (dir < 0) return false;
    struct isr_manifest manifest; char mh[65], pin[65], image[ISR_PATH];
    bool ok = isr_manifest(dir, &l, &manifest, mh) && isr_self(&l, &manifest);
    if (ok) ok = isr_assets(dir, &manifest, pin);
    if (ok) ok = zcl_path_join(image, sizeof(image), l.dir, isr_names[ISR_GAME]);
    if (ok) ok = app_installed_source_load(l.dir, pin, image, out, why, cap);
    if (ok) ok = isr_retained(out, &manifest);
    if (ok) ok = isr_recheck(dir, &l, &manifest, mh, pin);
    if (close(dir) != 0) ok = false;
    return ok;
}
/* Recognize the installed layout before validating it, so a broken selector
 * cannot turn a selected kit into an unselected development toolchain. */
static int isr_toolchain_candidate(void)
{
#if defined(__APPLE__)
    struct isr_layout layout;
    return isr_layout(&layout) ? 1 : 0;
#else
    char exe[ISR_PATH], prefix[ISR_PATH], path[ISR_PATH];
    if (!isr_exe_path(exe, sizeof(exe))) return -1;
    size_t n = strlen(exe);
    if (n <= 8 || strcmp(exe + n - 8, "/bin/z23")) return 0;
    memcpy(prefix, exe, n - 8); prefix[n - 8] = 0;
    if (!zcl_path_join(path, sizeof(path), prefix, "share/z23/apps")) return -1;
    struct stat st;
    if (lstat(path, &st) == 0) return 1;
    if (errno != ENOENT) return -1;
    if (!zcl_path_join(path, sizeof(path), prefix, "bin/z23-skycombat")) return -1;
    if (lstat(path, &st) == 0) return S_ISLNK(st.st_mode) ? 1 : 0;
    return errno == ENOENT ? 0 : -1;
#endif
}
static bool isr_kit_bytes(int dir, int row, const struct isr_manifest *manifest,
    struct app_installed_source_bytes *out)
{
    int fd = openat(dir, isr_names[row], O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return false;
    struct platform_positioned_file_snapshot before;
    bool ok = isr_readable(fd, isr_limits[row], &before);
    if (ok) {
        out->bytes = zcl_malloc((size_t)before.size, "installed.toolchain.member");
        ok = out->bytes != NULL;
    }
    if (ok) {
        char digest[65];
        ok = isr_stream(fd, isr_limits[row], digest, out->bytes,
            (size_t)before.size, &out->length) &&
            !strcmp(digest, manifest->digest[row]);
    }
    if (close(fd) != 0) ok = false;
    return ok;
}
#if defined(ZCL_TESTING)
/* Exercise retained member verification, without impersonating an installed
 * executable or granting production toolchain selection authority. */
bool zcl_test_installed_toolchain_manifest(int dir, const char *wire, size_t length, bool mac);
bool zcl_test_installed_toolchain_manifest(int dir, const char *wire, size_t length, bool mac)
{
    if (!wire || length > ISR_MANIFEST) return false;
    char bytes[ISR_MANIFEST + 1]; struct isr_manifest manifest;
    memcpy(bytes, wire, length); bytes[length] = 0;
    struct app_installed_toolchain kit = {0};
    bool ok = isr_parse(bytes, length, &manifest, mac) &&
        manifest.digest[ISR_KIT_DESCRIPTOR][0] &&
        isr_kit_bytes(dir, ISR_KIT_DESCRIPTOR, &manifest, &kit.descriptor) &&
        isr_kit_bytes(dir, ISR_KIT_BUNDLE, &manifest, &kit.bundle);
    app_installed_toolchain_free(&kit);
    return ok;
}
#endif
static enum app_installed_toolchain_status isr_toolchain(
    struct app_installed_toolchain *out)
{
    int candidate = isr_toolchain_candidate();
    if (candidate == 0) return APP_INSTALLED_TOOLCHAIN_UNSELECTED;
    struct isr_layout layout;
    if (candidate < 0 || !isr_layout(&layout)) return APP_INSTALLED_TOOLCHAIN_REFUSED;
    int dir = isr_directory(layout.dir);
    if (dir < 0) return APP_INSTALLED_TOOLCHAIN_REFUSED;
    struct isr_manifest manifest; char hash[65];
    bool ok = isr_manifest(dir, &layout, &manifest, hash) && isr_self(&layout, &manifest);
    bool selected = ok && manifest.digest[ISR_KIT_DESCRIPTOR][0];
    if (selected) ok = isr_kit_bytes(dir, ISR_KIT_DESCRIPTOR, &manifest, &out->descriptor) &&
        isr_kit_bytes(dir, ISR_KIT_BUNDLE, &manifest, &out->bundle);
    if (ok) ok = isr_binding_matches(dir, &layout, hash) && isr_self(&layout, &manifest);
    if (close(dir) != 0) ok = false;
    return !ok ? APP_INSTALLED_TOOLCHAIN_REFUSED : selected ?
        APP_INSTALLED_TOOLCHAIN_VERIFIED : APP_INSTALLED_TOOLCHAIN_UNSELECTED;
}
#endif
void app_installed_toolchain_free(struct app_installed_toolchain *out)
{
    if (!out) return;
    free(out->descriptor.bytes); free(out->bundle.bytes);
    memset(out, 0, sizeof(*out));
}
enum app_installed_toolchain_status app_installed_toolchain_resolve(
    struct app_installed_toolchain *out, char *why, size_t cap)
{
    if (!out) {
        (void)app_installed_source_message(why, cap, "Toolchain resolution needs an output");
        return APP_INSTALLED_TOOLCHAIN_REFUSED;
    }
    app_installed_toolchain_free(out);
    enum app_installed_toolchain_status status = APP_INSTALLED_TOOLCHAIN_UNSELECTED;
#if defined(__linux__) || defined(__APPLE__)
    status = isr_toolchain(out);
#endif
    if (status != APP_INSTALLED_TOOLCHAIN_VERIFIED) app_installed_toolchain_free(out);
    (void)app_installed_source_message(why, cap,
        status == APP_INSTALLED_TOOLCHAIN_VERIFIED ? "Retained kit bytes match the installer manifest; semantic verification required" :
        status == APP_INSTALLED_TOOLCHAIN_UNSELECTED ? "No installed compiler kit selected" :
        "Installed compiler kit refused: layout, owner/mode, manifest, running image or member mismatch");
    return status;
}
bool app_installed_source_resolve(const char *app,
    struct app_installed_source *out, char *why, size_t cap)
{
    (void)app_installed_source_message(why, cap, "");
    if (out) app_installed_source_free(out);
    if (!out || !app || strcmp(app, "skycombat")) {
        (void)app_installed_source_message(why, cap, "Only installed skycombat is supported");
        return false;
    }
#if defined(__linux__) || defined(__APPLE__)
    if (isr_resolve(out, why, cap)) {
        (void)app_installed_source_message(why, cap,
            os_proc_self_exe_identity() == OS_PROC_IMAGE_IDENTITY_RUNNING_IMAGE ?
            "installer manifest verified; running-inode identity; recheck at consent/use" :
            "installer manifest verified; pathname identity only, not running-inode proof; recheck at consent/use");
        return true;
    }
    app_installed_source_free(out);
    if (why && cap && !why[0]) snprintf(why, cap,
        "Installed source refused: layout, owner/mode, manifest, running image or asset mismatch");
#else
    (void)app_installed_source_message(why, cap, "Installed source resolution unsupported on this platform");
#endif
    return false;
}
