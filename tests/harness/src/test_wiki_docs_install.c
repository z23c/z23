/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Installed-binary docs resolution for the two install layouts: a copy of the
 * CLI at <prefix>/bin/z23 and at <prefix>/lib/z23/generations/<hex>/z23, each
 * with the documentation tree at <prefix>/share/z23/docs, run from a
 * directory outside any checkout with no source root configured. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE 1
#endif
#include "test/test_core.h"

#include "json/json.h"
#include "base/hex.h"
#include "crypto/sha256.h"
#include "util/spawn.h"
#include "command/native_app_launch.h"
#include "command/native_command.h"
#include "vcs/source_bundle.h"
#include "vcs/vcs.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define WI_EXE "build/bin/z23-dev"
#define WI_DEADLINE_MS 60000
#define WI_GEN "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

struct wi_release {
    char base[PATH_MAX], release[PATH_MAX], prefix[PATH_MAX], script[PATH_MAX];
    char manifest[PATH_MAX], root[65], pin[65];
};
static bool wi_copy(const char *src, const char *dst, mode_t mode);
static bool wi_mkpath(const char *base, const char *rel);
static int wi_run_installer(const struct wi_release *f);

static bool wi_write(const char *path, const void *bytes, size_t size, mode_t mode)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fwrite(bytes, 1, size, f) == size;
    return fclose(f) == 0 && ok && chmod(path, mode) == 0;
}

static bool wi_sha256(const char *path, char out[65])
{
    FILE *file = fopen(path, "rb"); if (!file) return false;
    struct sha256_ctx hash; sha256_init(&hash);
    unsigned char buf[8192], digest[32]; size_t n;
    while ((n = fread(buf, 1, sizeof(buf), file)) != 0) sha256_write(&hash, buf, n);
    bool ok = !ferror(file);
    if (fclose(file) != 0) ok = false;
    if (ok) { sha256_finalize(&hash, digest); zcl_hex_encode(digest, sizeof(digest), out); }
    return ok;
}

static bool wi_fixture_bundle(struct wi_release *f)
{
    char docs[PATH_MAX], path[PATH_MAX]; uint8_t root[32], *wire = NULL; size_t len = 0;
    if (snprintf(docs, sizeof(docs), "%s/docs-src", f->base) >= (int)sizeof(docs) ||
        mkdir(docs, 0700) != 0 || snprintf(path, sizeof(path), "%s/README.md", docs) >= (int)sizeof(path) ||
        !wi_write(path, "# Offline docs\n", 15, 0600)) return false;
    if (snprintf(path, sizeof(path), "%s/page.md", docs) >= (int)sizeof(path) ||
        !wi_write(path, "# Page\n", 7, 0600)) return false;
    if (vcs_tree_capture_path(docs, root) != VCS_OK ||
        vcs_source_bundle_create(docs, root, &wire, &len, NULL) != VCS_SOURCE_BUNDLE_OK) return false;
    zcl_hex_encode(root, sizeof(root), f->root);
    int n = snprintf(path, sizeof(path), "%s/docs.bundle", f->release);
    bool ok = n > 0 && (size_t)n < sizeof(path) && wi_write(path, wire, len, 0600);
    free(wire);
    n = snprintf(path, sizeof(path), "%s/docs.root", f->release);
    char text[66]; (void)snprintf(text, sizeof(text), "%s\n", f->root);
    return ok && n > 0 && (size_t)n < sizeof(path) && wi_write(path, text, 65, 0600);
}

static bool wi_fixture_manifest(struct wi_release *f, unsigned docs)
{
    static const char *const names[] = {"AGENT_CARD.md", "z23", "zclassic23", "z23-acme",
        "zclassic23-acme", "z23-package-verify", "zclassic23-package-verify", "docs.bundle", "docs.root"};
    FILE *out = fopen(f->manifest, "wb"); if (!out) return false;
    bool ok = true; char path[PATH_MAX], hash[65];
    size_t count = 7u + docs;
    for (size_t i = 0; ok && i < count; ++i) {
        int n = snprintf(path, sizeof(path), "%s/%s", f->release, names[i]);
        ok = n > 0 && (size_t)n < sizeof(path) && wi_sha256(path, hash) &&
            fprintf(out, "%s  %s\n", hash, names[i]) > 0;
    }
    return fclose(out) == 0 && ok && wi_sha256(f->manifest, f->pin);
}

static bool wi_fixture_runtime(struct wi_release *f, bool replacement)
{
    static const char *const names[] = {"z23", "zclassic23", "z23-acme", "zclassic23-acme",
        "z23-package-verify", "zclassic23-package-verify"};
    char exe[PATH_MAX], text[PATH_MAX + 160], path[PATH_MAX];
    if (!realpath(WI_EXE, exe) || strchr(exe, '\'')) return false;
    int n = snprintf(text, sizeof(text), "#!/bin/sh\n# fixture %d\nif [ \"$1\" = -version ]; then printf 'tor: full\\n'; exit 0; fi\nexec '%s' \"$@\"\n", replacement, exe);
    if (n <= 0 || (size_t)n >= sizeof(text)) return false;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        n = snprintf(path, sizeof(path), "%s/%s", f->release, names[i]);
        if (n <= 0 || (size_t)n >= sizeof(path) || !wi_write(path, text, strlen(text), 0700)) return false;
    }
    n = snprintf(path, sizeof(path), "%s/AGENT_CARD.md", f->release);
    return n > 0 && (size_t)n < sizeof(path) && wi_write(path, "# Agent\n", 8, 0600);
}

/* Observe the selected route, including an older binary's unknown leaf and a
 * new binary that refuses materialization before any installation. */
static bool wi_route_runtime(struct wi_release *f, int behavior)
{
    char exe[PATH_MAX], path[PATH_MAX], text[PATH_MAX * 3];
    if (!realpath(WI_EXE, exe) || strchr(exe, '\'') || strchr(f->base, '\'')) return false;
    int n = snprintf(text, sizeof(text),
        "#!/bin/sh\nif [ \"$1\" = -version ]; then echo 'tor: full'; exit 0; fi\n"
        "if [ \"$1 $2 $3 $4 $5\" = 'zcode workspace source bundle materialize' ]; then "
        "echo materialize >>'%s/route'; if [ %d = 1 ]; then echo '{\"error\":{\"code\":\"UNKNOWN_COMMAND\",\"evidence\":\"zcode.workspace.source.bundle.materialize\"}}'; exit 2; fi; "
        "if [ %d = 2 ]; then echo '{\"error\":{\"code\":\"SOURCE_BUNDLE_IMPORT_REFUSED\"}}'; exit 2; fi; "
        "if [ %d = 3 ]; then echo '{\"error\":{\"code\":\"DISPOSABLE_PATH_UNSUPPORTED\"}}'; exit 2; fi; fi\n"
        "if [ \"$1 $2 $3 $4 $5\" = 'zcode workspace source bundle checkout' ]; then echo checkout >>'%s/route'; fi\n"
        "exec '%s' \"$@\"\n", f->base, behavior, behavior, behavior, f->base, exe);
    if (n <= 0 || (size_t)n >= sizeof(text)) return false;
    const char *names[] = {"z23", "zclassic23"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        n = snprintf(path, sizeof(path), "%s/%s", f->release, names[i]);
        if (n <= 0 || (size_t)n >= sizeof(path) || !wi_write(path, text, strlen(text), 0700))
            return false;
    }
    return true;
}

static bool wi_route_is(const struct wi_release *f, const char *expected)
{
    char path[PATH_MAX], text[64];
    int n = snprintf(path, sizeof(path), "%s/route", f->base);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    FILE *file = fopen(path, "rb"); if (!file) return false;
    size_t used = fread(text, 1, sizeof(text) - 1, file);
    bool ok = !ferror(file);
    if (fclose(file) != 0) ok = false;
    text[used] = '\0';
    return ok && !strcmp(text, expected) && unlink(path) == 0;
}

static bool wi_route_controls(struct wi_release *f)
{
    if (!wi_route_runtime(f, 1) || !wi_fixture_manifest(f, 2) ||
        wi_run_installer(f) != 0 || !wi_route_is(f, "materialize\ncheckout\n")) return false;
    if (!wi_route_runtime(f, 3) || !wi_fixture_manifest(f, 2) ||
        wi_run_installer(f) != 0 || !wi_route_is(f, "materialize\ncheckout\n")) return false;
    if (!wi_route_runtime(f, 2) || !wi_fixture_manifest(f, 2) ||
        wi_run_installer(f) == 0 || !wi_route_is(f, "materialize\n")) return false;
    return wi_route_runtime(f, 0) && wi_fixture_manifest(f, 2);
}

static bool wi_fixture_paths(struct wi_release *f)
{
    if (!test_mkdtemp(f->base, sizeof(f->base), "wiki_release")) return false;
    int a = snprintf(f->release, sizeof(f->release), "%s/release", f->base);
    int b = snprintf(f->prefix, sizeof(f->prefix), "%s/prefix", f->base);
    int c = snprintf(f->script, sizeof(f->script), "%s/standalone/bin/install_z23.sh", f->base);
    int d = snprintf(f->manifest, sizeof(f->manifest), "%s/SHA256SUMS", f->release);
    return a > 0 && (size_t)a < sizeof(f->release) && b > 0 && (size_t)b < sizeof(f->prefix) &&
        c > 0 && (size_t)c < sizeof(f->script) && d > 0 && (size_t)d < sizeof(f->manifest);
}

static bool wi_fixture_create(struct wi_release *f)
{
    char source[PATH_MAX];
    return wi_fixture_paths(f) && mkdir(f->release, 0700) == 0 && wi_mkpath(f->base, "standalone/bin") &&
        realpath("tools/scripts/install_z23.sh", source) &&
        wi_copy(source, f->script, 0700) && wi_fixture_runtime(f, false) && wi_fixture_bundle(f) && wi_fixture_manifest(f, 2);
}

static int wi_run_installer(const struct wi_release *f)
{
    char source[PATH_MAX + 16], pin[96], out[4096]; bool timeout = false;
    int n = snprintf(source, sizeof(source), "--source=%s", f->release);
    int m = snprintf(pin, sizeof(pin), "--manifest-sha256=%s", f->pin);
    if (n <= 0 || (size_t)n >= sizeof(source) || m <= 0 || (size_t)m >= sizeof(pin)) return -1;
    const char *argv[] = {"bash", f->script, source, pin, NULL};
    int rc = zcl_spawn_capture_merged_in_dir_observed(argv, f->base, out, sizeof(out), WI_DEADLINE_MS, &timeout);
    if (rc || timeout) printf("  [installer rc=%d timeout=%d output=%.3000s]\n", rc, timeout, out);
    return timeout ? -1 : rc;
}

static bool wi_mkpath(const char *base, const char *rel)
{
    char path[PATH_MAX + 128];
    size_t n = (size_t)snprintf(path, sizeof(path), "%s/%s", base, rel);
    for (size_t i = strlen(base) + 1; i <= n && n < sizeof(path); i++) {
        if (path[i] != '/' && path[i] != '\0')
            continue;
        char saved = path[i];
        path[i] = '\0';
        if (mkdir(path, 0700) != 0 && errno != EEXIST)
            return false;
        path[i] = saved;
    }
    return true;
}

static bool wi_copy(const char *src, const char *dst, mode_t mode)
{
    FILE *in = fopen(src, "rb"), *out = fopen(dst, "wb");
    char buf[65536];
    size_t got;
    bool ok = in && out;
    while (ok && (got = fread(buf, 1, sizeof(buf), in)) > 0)
        ok = fwrite(buf, 1, got, out) == got;
    if (in)
        fclose(in);
    ok = (out ? fclose(out) == 0 : false) && ok;
    return ok && chmod(dst, mode) == 0;
}

/* Lays out <prefix>/<exe_rel> (a copy of the CLI) and
 * <prefix>/share/z23/docs/README.md. */
static bool wi_install(const char *prefix, const char *exe_rel,
                       char *exe, size_t cap)
{
    char path[PATH_MAX + 192], dir[PATH_MAX + 192];
    snprintf(exe, cap, "%s/%s", prefix, exe_rel);
    snprintf(dir, sizeof(dir), "%s", exe_rel);
    *strrchr(dir, '/') = '\0';
    snprintf(path, sizeof(path), "%s/share/z23/docs/README.md", prefix);
    if (!wi_mkpath(prefix, dir) || !wi_mkpath(prefix, "share/z23/docs") ||
        !wi_copy(WI_EXE, exe, 0700))
        return false;
    FILE *fp = fopen(path, "wb");
    bool ok = fp && fputs("# Installed docs\n\nFound by path.\n", fp) >= 0;
    return (fp ? fclose(fp) == 0 : false) && ok;
}

static void wi_drop(const char *prefix, const char *exe_rel)
{
    char path[PATH_MAX + 192];
    snprintf(path, sizeof(path), "%s/share/z23/docs/README.md", prefix);
    TEST_DISCARD(unlink(path));
    snprintf(path, sizeof(path), "%s/%s", prefix, exe_rel);
    TEST_DISCARD(unlink(path));
    for (char *p = path + strlen(path); p > path + strlen(prefix); p--) {
        if (*p != '/')
            continue;
        *p = '\0';
        TEST_DISCARD(rmdir(path));
    }
    snprintf(path, sizeof(path), "%s/share/z23/docs", prefix);
    TEST_DISCARD(rmdir(path));
    snprintf(path, sizeof(path), "%s/share/z23", prefix);
    TEST_DISCARD(rmdir(path));
    snprintf(path, sizeof(path), "%s/share", prefix);
    TEST_DISCARD(rmdir(path));
    TEST_DISCARD(rmdir(prefix));
}

static bool wi_title(const char *exe, const char *cwd, char *title, size_t cap)
{
    char out[16384];
    const char *argv[] = { exe, "wiki", NULL };
    struct json_value reply;
    bool timed_out = false;
    TEST_DISCARD(unsetenv("ZCL_DEV_SOURCE_ROOT"));
    int rc = zcl_spawn_capture_in_dir_observed(argv, cwd, out, sizeof(out),
                                               WI_DEADLINE_MS, &timed_out);
    json_init(&reply);
    bool ok = rc == 0 && !timed_out && json_read(&reply, out, strlen(out));
    const char *t = ok ? json_get_str(json_get(json_get(&reply, "data"),
                                               "title")) : NULL;
    snprintf(title, cap, "%s", t ? t : "");
    json_free(&reply);
    return t != NULL;
}

static int wi_layout(const char *name, const char *exe_rel)
{
    int failures = 0;
    char base[PATH_MAX], prefix[PATH_MAX + 16], exe[PATH_MAX + 192];
    char title[256];
    bool made = false;
    TEST("wiki docs install: an installed layout finds <prefix>/share/z23/docs") {
        ASSERT(test_mkdtemp(base, sizeof(base), "wiki_docs_install") != NULL);
        made = true;
        snprintf(prefix, sizeof(prefix), "%s/%s", base, name);
        ASSERT(wi_mkpath(base, name));
        ASSERT(wi_install(prefix, exe_rel, exe, sizeof(exe)));
        ASSERT(wi_title(exe, base, title, sizeof(title)));
        ASSERT_STR_EQ(title, "Installed docs");
        PASS();
    } _test_next:;
    if (made) {
        wi_drop(prefix, exe_rel);
        TEST_DISCARD(rmdir(base));
    }
    return failures;
}

static bool wi_preserved_docs(const struct wi_release *f)
{
    char exe[PATH_MAX], source[PATH_MAX], title[256];
    int n = snprintf(exe, sizeof(exe), "%s/bin/wiki-probe", f->prefix);
    return n > 0 && (size_t)n < sizeof(exe) && realpath(WI_EXE, source) &&
        wi_copy(source, exe, 0700) && wi_title(exe, f->base, title, sizeof(title)) &&
        !strcmp(title, "Offline docs");
}

static bool wi_bad_root(struct wi_release *f)
{
    char path[PATH_MAX], wrong[66];
    memset(wrong, '0', 64); wrong[64] = '\n'; wrong[65] = 0;
    int n = snprintf(path, sizeof(path), "%s/docs.root", f->release);
    return n > 0 && (size_t)n < sizeof(path) && wi_write(path, wrong, 65, 0600) && wi_fixture_manifest(f, 2);
}

static bool wi_bad_bundle(struct wi_release *f)
{
    char path[PATH_MAX], root[66];
    int n = snprintf(path, sizeof(path), "%s/docs.root", f->release);
    (void)snprintf(root, sizeof(root), "%s\n", f->root);
    if (n <= 0 || (size_t)n >= sizeof(path) || !wi_write(path, root, 65, 0600) ||
        !wi_fixture_manifest(f, 2)) return false;
    n = snprintf(path, sizeof(path), "%s/docs.bundle", f->release);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    FILE *file = fopen(path, "r+b"); if (!file) return false;
    int c = fgetc(file); bool ok = c != EOF && fseek(file, 0, SEEK_SET) == 0 && fputc(c ^ 1, file) != EOF;
    return fclose(file) == 0 && ok;
}

static bool wi_isolated_env(const struct wi_release *f)
{
    static const char *const keys[] = {"Z23_UNIT_DIR", "Z23_DATADIR", "XDG_CONFIG_HOME",
        "XDG_DATA_HOME", "XDG_STATE_HOME", "TMPDIR"};
    char path[PATH_MAX];
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        int n = snprintf(path, sizeof(path), "%s/private-%zu", f->base, i);
        if (n <= 0 || (size_t)n >= sizeof(path) || mkdir(path, 0700) != 0 || setenv(keys[i], path, 1) != 0)
            return false;
    }
    return true;
}

static bool wi_legacy_install(struct wi_release *f)
{
    char prefix[PATH_MAX], docs[PATH_MAX];
    int n = snprintf(prefix, sizeof(prefix), "%s/legacy", f->base);
    int m = snprintf(docs, sizeof(docs), "%s/share/z23/docs", prefix);
    return n > 0 && (size_t)n < sizeof(prefix) && m > 0 && (size_t)m < sizeof(docs) &&
        setenv("Z23_INSTALL_PREFIX", prefix, 1) == 0 && wi_fixture_manifest(f, 0) &&
        wi_run_installer(f) == 0 && access(docs, F_OK) != 0 && errno == ENOENT;
}

static void wi_restore_env(const char *key, char *value)
{
    if (value) { (void)setenv(key, value, 1); free(value); }
    else (void)unsetenv(key);
}

static bool wi_payload_unchanged(const struct wi_release *f, const char *expected)
{
    char path[PATH_MAX], actual[65];
    int n = snprintf(path, sizeof(path), "%s/bin/z23", f->prefix);
    return n > 0 && (size_t)n < sizeof(path) && wi_sha256(path, actual) &&
        !strcmp(actual, expected) && wi_preserved_docs(f);
}

static int wi_standalone_release(void)
{
    int failures = 0; struct wi_release f = {0};
    const char *keys[] = {"Z23_INSTALL_PREFIX", "Z23_SKIP_SYSTEMD", "Z23_INSTALL_DOCS_DIR",
        "Z23_UNIT_DIR", "Z23_DATADIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "TMPDIR"};
    char *saved[sizeof(keys) / sizeof(keys[0])] = {0};
    bool env_ok = true;
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        const char *value = getenv(keys[i]);
        if (value && !(saved[i] = strdup(value))) env_ok = false;
    }
    if (!env_ok) {
        for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) free(saved[i]);
        return 1;
    }
    TEST("wiki docs install: standalone pinned release installs verified docs and refuses wrong root") {
        ASSERT(wi_fixture_create(&f));
        ASSERT(setenv(keys[0], f.prefix, 1) == 0 && setenv(keys[1], "1", 1) == 0 &&
            unsetenv(keys[2]) == 0 && wi_isolated_env(&f));
        ASSERT(wi_route_runtime(&f, 0) && wi_fixture_manifest(&f, 2));
        int rc = wi_run_installer(&f); ASSERT_EQ(rc, 0);
        ASSERT(wi_route_is(&f, "materialize\n"));
        ASSERT(wi_preserved_docs(&f));
        ASSERT(wi_route_controls(&f));
        char installed[PATH_MAX], original[65];
        ASSERT(snprintf(installed, sizeof(installed), "%s/bin/z23", f.prefix) > 0);
        ASSERT(wi_sha256(installed, original));
        ASSERT(wi_fixture_runtime(&f, true));
        ASSERT(wi_bad_root(&f));
        ASSERT(wi_run_installer(&f) != 0);
        ASSERT(wi_payload_unchanged(&f, original));
        ASSERT(wi_bad_bundle(&f));
        ASSERT(wi_run_installer(&f) != 0);
        ASSERT(wi_payload_unchanged(&f, original));
        ASSERT(wi_fixture_manifest(&f, 2));
        ASSERT(wi_run_installer(&f) != 0);
        ASSERT(wi_payload_unchanged(&f, original));
        ASSERT(wi_fixture_manifest(&f, 1));
        ASSERT(wi_run_installer(&f) != 0);
        ASSERT(wi_payload_unchanged(&f, original));
        ASSERT(wi_legacy_install(&f));
        PASS();
    } _test_next:;
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) wi_restore_env(keys[i], saved[i]);
    if (f.base[0]) TEST_DISCARD(test_rm_rf_recursive(f.base));
    return failures;
}

/* Fixture wrappers delegate only to the locally built development executable. */
static bool wi_apps_runtime(struct wi_release *f, bool tasks)
{
    char source[PATH_MAX], target[PATH_MAX];
    if (!wi_fixture_runtime(f, false)) return false;
    return snprintf(source, sizeof(source), "%s/z23", f->release) < (int)sizeof(source) &&
        snprintf(target, sizeof(target), "%s/%s", f->release, tasks ? "z23-tasks" : "z23-skycombat") < (int)sizeof(target) &&
        wi_copy(source, target, 0700);
}

static bool wi_apps_members(struct wi_release *f)
{
    static const char *const data[] = {"AGENT_CARD.md", "installed-source.json",
        "source.bundle", "manifest.wire", "recipe.wire", "app-build.wire"};
    static const char *const desktop[] = {"org.zclassic.SkyCombat.desktop",
        "org.zclassic.ZClassic23.desktop", "org.zclassic.ZClassic23.svg", "org.zclassic.ZClassic23.xml"};
    char target[PATH_MAX], source[PATH_MAX];
    for (size_t i = 0; i < sizeof(data) / sizeof(data[0]); ++i) {
        if (snprintf(target, sizeof(target), "%s/%s", f->release, data[i]) >= (int)sizeof(target) ||
            !wi_write(target, "fixture\n", 8, 0600)) return false;
    }
    for (size_t i = 0; i < sizeof(desktop) / sizeof(desktop[0]); ++i) {
        if (snprintf(source, sizeof(source), "platform/packaging/linux/%s", desktop[i]) >= (int)sizeof(source) ||
            snprintf(target, sizeof(target), "%s/%s", f->release, desktop[i]) >= (int)sizeof(target) ||
            !wi_copy(source, target, 0600)) return false;
    }
    return true;
}

static bool wi_apps_release(struct wi_release *f, bool tasks)
{
    char script[PATH_MAX];
    return wi_fixture_paths(f) && mkdir(f->release, 0700) == 0 && wi_mkpath(f->base, "standalone/bin") &&
        realpath("tools/scripts/install_z23.sh", script) && wi_copy(script, f->script, 0700) &&
        wi_apps_runtime(f, tasks) && wi_apps_members(f);
}


static bool wi_apps_manifest(struct wi_release *f, bool tasks)
{
    static const char *const names[] = {"AGENT_CARD.md", "z23", "zclassic23",
        "z23-acme", "zclassic23-acme", "z23-package-verify", "zclassic23-package-verify",
        "installed-source.json", "source.bundle", "manifest.wire", "recipe.wire", "app-build.wire",
        "org.zclassic.SkyCombat.desktop", "org.zclassic.ZClassic23.desktop",
        "org.zclassic.ZClassic23.svg", "org.zclassic.ZClassic23.xml"};
    FILE *out = fopen(f->manifest, "wb"); if (!out) return false;
    char path[PATH_MAX], hash[65]; bool ok = true;
    for (size_t i = 0; ok && i <= sizeof(names) / sizeof(names[0]); ++i) {
        const char *name = i == sizeof(names) / sizeof(names[0]) ? (tasks ? "z23-tasks" : "z23-skycombat") : names[i];
        int n = snprintf(path, sizeof(path), "%s/%s", f->release, name);
        ok = n > 0 && (size_t)n < sizeof(path) && wi_sha256(path, hash) && fprintf(out, "%s  %s\n", hash, name) > 0;
    }
    return fclose(out) == 0 && ok && wi_sha256(f->manifest, f->pin);
}

#if !defined(__APPLE__)
static bool wi_apps_desktop(const struct wi_release *f, bool tasks)
{
    char path[PATH_MAX], desktop[8192];
    int n = snprintf(path, sizeof(path), "%s/data/applications/org.zclassic.%s.desktop",
                     f->base, tasks ? "Tasks" : "SkyCombat");
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    FILE *file = fopen(path, "rb"); if (!file) return false;
    size_t used = fread(desktop, 1, sizeof(desktop) - 1, file);
    bool ok = !ferror(file);
    ok = fclose(file) == 0 && ok;
    desktop[used] = '\0';
    return ok && strstr(desktop, tasks ? "Name=Tasks\n" : "Name=Sky Combat\n") &&
        strstr(desktop, tasks ? " app open tasks " : " app open skycombat ") &&
        strstr(desktop, "prefix space/bin/z23");
}

#endif

static bool wi_apps_desktop_if_linux(const struct wi_release *f, bool tasks)
{
#if defined(__APPLE__)
    (void)f; (void)tasks;
    return true;
#else
    return wi_apps_desktop(f, tasks);
#endif
}

static bool wi_apps_output(struct wi_release *f, bool tasks)
{
    char source[PATH_MAX + 16], pin[96], out[8192]; bool timeout = false;
    int n = snprintf(source, sizeof(source), "--source=%s", f->release);
    int m = snprintf(pin, sizeof(pin), "--manifest-sha256=%s", f->pin);
    if (n <= 0 || (size_t)n >= sizeof(source) || m <= 0 || (size_t)m >= sizeof(pin)) return false;
    const char *argv[] = {"bash", f->script, "--apps", source, pin, NULL};
    int rc = zcl_spawn_capture_merged_in_dir_observed(argv, f->base, out, sizeof(out), WI_DEADLINE_MS, &timeout);
    if (rc || timeout) { printf("  [apps installer rc=%d timeout=%d output=%.3000s]\n", rc, timeout, out); return false; }
    const char *hint = tasks ? "app open tasks --datadir=" : "app open skycombat --datadir=";
    char parent[PATH_MAX]; struct stat st;
    bool parent_ready = !tasks || (snprintf(parent, sizeof(parent), "%s/home/.local/share", f->base) < (int)sizeof(parent) &&
        lstat(parent, &st) == 0 && S_ISDIR(st.st_mode) && !(st.st_mode & 0022));
    return parent_ready && strstr(out, hint) && strstr(out, "prefix\\ space/bin/z23") && wi_apps_desktop_if_linux(f, tasks);
}

static bool wi_apps_mock(const struct wi_release *f, char *path, size_t cap)
{
    char mock[PATH_MAX], tool[PATH_MAX];
    const char *old_path = getenv("PATH");
    if (!old_path || snprintf(mock, sizeof(mock), "%s/mock", f->base) >= (int)sizeof(mock) ||
        mkdir(mock, 0700) != 0 || snprintf(path, cap, "%s:%s", mock, old_path) >= (int)cap) return false;
    const char *names[] = {"update-mime-database", "update-desktop-database"};
    for (size_t i = 0; i < 2; ++i) {
        if (snprintf(tool, sizeof(tool), "%s/%s", mock, names[i]) >= (int)sizeof(tool) ||
            !wi_write(tool, "#!/bin/sh\nexit 0\n", 17, 0700)) return false;
    }
    return true;
}

static bool wi_apps_dirs(const struct wi_release *f, char *home, char *data, char *prefix, char *state)
{
    return snprintf(home, PATH_MAX, "%s/home", f->base) < PATH_MAX &&
        snprintf(data, PATH_MAX, "%s/data", f->base) < PATH_MAX &&
        snprintf(prefix, PATH_MAX, "%s/prefix space", f->base) < PATH_MAX &&
        snprintf(state, PATH_MAX, "%s/state", f->base) < PATH_MAX &&
        mkdir(home, 0700) == 0 && mkdir(data, 0700) == 0 && mkdir(state, 0700) == 0;
}


/* The installer fixtures are Linux-shaped (XDG desktop entries); name that platform
 * so a macOS host does not run them as Darwin. Darwin cases override it. */
static bool wi_apps_env(struct wi_release *f, const char *const keys[8])
{
    char home[PATH_MAX], data[PATH_MAX], prefix[PATH_MAX], state[PATH_MAX], path[PATH_MAX * 2];
    if (!wi_apps_mock(f, path, sizeof(path))) return false;
    return wi_apps_dirs(f, home, data, prefix, state) &&
        setenv(keys[0], home, 1) == 0 && setenv(keys[1], data, 1) == 0 &&
        setenv(keys[2], prefix, 1) == 0 && setenv(keys[3], "1", 1) == 0 && unsetenv(keys[4]) == 0 &&
        setenv(keys[5], path, 1) == 0 && setenv(keys[6], "Linux", 1) == 0 && setenv(keys[7], state, 1) == 0;
}

static bool wi_apps_case(bool tasks)
{
    struct wi_release f = {0};
    const char *keys[] = {"HOME", "XDG_DATA_HOME", "Z23_INSTALL_PREFIX", "Z23_SKIP_SYSTEMD", "Z23_INSTALL_DOCS_DIR", "PATH", "Z23_INSTALL_TEST_PLATFORM", "XDG_STATE_HOME"};
    char *saved[8] = {0};
    for (size_t i = 0; i < 8; ++i) { const char *v = getenv(keys[i]); if (v && !(saved[i] = strdup(v))) return false; }
    bool ok = wi_apps_release(&f, tasks) && wi_apps_manifest(&f, tasks) &&
        wi_apps_env(&f, keys) && wi_apps_output(&f, tasks);
    for (size_t i = 0; i < 8; ++i) wi_restore_env(keys[i], saved[i]);
    if (f.base[0]) TEST_DISCARD(test_rm_rf_recursive(f.base));
    return ok;
}


static bool wi_apps_symlink_refused(void)
{
    struct wi_release f = {0};
    const char *keys[] = {"HOME", "XDG_DATA_HOME", "Z23_INSTALL_PREFIX", "Z23_SKIP_SYSTEMD", "Z23_INSTALL_DOCS_DIR", "PATH", "Z23_INSTALL_TEST_PLATFORM", "XDG_STATE_HOME"};
    char *saved[8] = {0}, linkpath[PATH_MAX], target[PATH_MAX], source[PATH_MAX + 16], pin[96], output[8192];
    for (size_t i = 0; i < 8; ++i) { const char *v = getenv(keys[i]); if (v && !(saved[i] = strdup(v))) return false; }
    bool ok = wi_apps_release(&f, true) && wi_apps_manifest(&f, true) && wi_apps_env(&f, keys);
    if (ok) {
        snprintf(linkpath, sizeof(linkpath), "%s/home/.local", f.base);
        snprintf(target, sizeof(target), "%s/data", f.base);
        snprintf(source, sizeof(source), "--source=%s", f.release);
        snprintf(pin, sizeof(pin), "--manifest-sha256=%s", f.pin);
        const char *argv[] = {"bash", f.script, "--apps", source, pin, NULL}; bool timeout = false;
        ok = symlink(target, linkpath) == 0 && zcl_spawn_capture_merged_in_dir_observed(argv, f.base, output, sizeof(output), WI_DEADLINE_MS, &timeout) != 0 && !timeout && strstr(output, "app profile lookup refused");
        struct stat st;
        ok = ok && snprintf(target, sizeof(target), "%s/data/share", f.base) < (int)sizeof(target) && lstat(target, &st) != 0 && errno == ENOENT;
    }
    for (size_t i = 0; i < 8; ++i) wi_restore_env(keys[i], saved[i]);
    if (f.base[0]) TEST_DISCARD(test_rm_rf_recursive(f.base));
    return ok;
}

static bool wi_profile_install(const struct wi_release *f, const char *profile, char *output, size_t cap, bool success)
{
    char source[PATH_MAX + 16], pin[96], option[PATH_MAX + 32]; bool timeout = false;
    if (snprintf(source, sizeof(source), "--source=%s", f->release) >= (int)sizeof(source) ||
        snprintf(pin, sizeof(pin), "--manifest-sha256=%s", f->pin) >= (int)sizeof(pin) ||
        snprintf(option, sizeof(option), "--app-datadir=%s", profile ? profile : "") >= (int)sizeof(option)) return false;
    const char *argv[] = {"bash", f->script, "--apps", source, pin, profile ? option : NULL, NULL};
    int rc = zcl_spawn_capture_merged_in_dir_observed(argv, f->base, output, cap, WI_DEADLINE_MS, &timeout);
    return !timeout && (success ? rc == 0 : rc != 0);
}

static bool wi_profile_legacy(struct wi_release *f)
{
    const char legacy[] = "#!/bin/sh\nif [ \"$1\" = -version ]; then echo 'tor: full'; exit 0; fi\n"
        "echo '{\"error\":{\"code\":\"UNKNOWN_COMMAND\",\"evidence\":\"ops.host.app-profile\"}}'; exit 2\n";
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/z23", f->release) >= (int)sizeof(path) || !wi_write(path, legacy, sizeof(legacy) - 1, 0700)) return false;
    if (snprintf(path, sizeof(path), "%s/zclassic23", f->release) >= (int)sizeof(path) || !wi_write(path, legacy, sizeof(legacy) - 1, 0700)) return false;
    return wi_apps_manifest(f, true);
}

static bool wi_profile_desktops(const struct wi_release *f)
{
#if defined(__APPLE__)
    (void)f; return true;
#else
    static const char *const names[] = {"org.zclassic.Tasks.desktop", "org.zclassic.ZClassic23.desktop", "org.zclassic.ZClassic23.Library.desktop"};
    static const char *const commands[] = {"app open tasks", "app receive --preview", "app library"};
    char path[PATH_MAX], bytes[8192];
    for (size_t i = 0; i < 3; ++i) {
        if (snprintf(path, sizeof(path), "%s/data/applications/%s", f->base, names[i]) >= (int)sizeof(path)) return false;
        FILE *in = fopen(path, "rb"); if (!in) return false;
        size_t n = fread(bytes, 1, sizeof(bytes) - 1, in); bool ok = !ferror(in);
        ok = fclose(in) == 0 && ok; bytes[n] = 0;
        if (!ok || !strstr(bytes, "chosen ' profile") || !strstr(bytes, commands[i])) return false;
    }
    return true;
#endif
}

static bool wi_profile_token(const struct wi_release *f, const char *profile, char token[65])
{
    char exe[PATH_MAX], path[PATH_MAX + 16], output[4096]; bool timeout = false;
    if (!realpath(WI_EXE, exe) || snprintf(path, sizeof(path), "--path=%s", profile) >= (int)sizeof(path)) return false;
    const char *argv[] = {exe, "ops", "host", "app-profile", "check", path, "--field=plan_id", NULL};
    if (zcl_spawn_capture_merged_in_dir_observed(argv, f->base, output, sizeof(output), WI_DEADLINE_MS, &timeout) || timeout ||
        strncmp(output, "plan_id=", 8) || strlen(output) != 73 || output[72] != '\n') return false;
    memcpy(token, output + 8, 64); token[64] = 0; return true;
}

static bool wi_profile_prepare_stale(const struct wi_release *f, char token[65])
{
    char second[PATH_MAX];
    return snprintf(second, sizeof(second), "%s/second profile", f->base) < (int)sizeof(second) &&
        mkdir(second, 0700) == 0 && wi_profile_token(f, second, token);
}

static bool wi_profile_stale(const struct wi_release *f, const char *token)
{
    char exe[PATH_MAX], second[PATH_MAX], path[PATH_MAX + 16], plan[80], output[4096]; bool timeout = false;
    if (!realpath(WI_EXE, exe) || snprintf(second, sizeof(second), "%s/second profile", f->base) >= (int)sizeof(second) ||
        snprintf(path, sizeof(path), "--path=%s", second) >= (int)sizeof(path) ||
        snprintf(plan, sizeof(plan), "--plan_id=%s", token) >= (int)sizeof(plan)) return false;
    const char *argv[] = {exe, "ops", "host", "app-profile", "set", path, plan, "--json", NULL};
    int rc = zcl_spawn_capture_merged_in_dir_observed(argv, f->base, output, sizeof(output), WI_DEADLINE_MS, &timeout);
    return !timeout && rc != 0 && strstr(output, "APP_PROFILE_REFUSED");
}

struct wi_profile_record { char path[PATH_MAX]; unsigned char bytes[1200]; size_t length; };
static bool wi_profile_record_read(const struct wi_release *f, struct wi_profile_record *saved)
{
    if (snprintf(saved->path, sizeof(saved->path), "%s/state/z23/apps/desktop-profile", f->base) >= (int)sizeof(saved->path)) return false;
    FILE *in = fopen(saved->path, "rb"); if (!in) return false;
    saved->length = fread(saved->bytes, 1, sizeof(saved->bytes), in);
    bool ok = !ferror(in) && saved->length > 0 && saved->length < sizeof(saved->bytes);
    return fclose(in) == 0 && ok;
}

static bool wi_profile_corrupt(const struct wi_release *f, const char *profile)
{
    char exe[PATH_MAX], output[4096]; bool timeout = false; struct wi_profile_record saved;
    (void)profile; static const char bad[] = {'/', 'x', 0, 'y'};
    if (!realpath(WI_EXE, exe) || !wi_profile_record_read(f, &saved) ||
        !wi_write(saved.path, bad, sizeof(bad), 0600)) return false;
    const char *argv[] = {exe, "ops", "host", "app-profile", "get", "--json", NULL};
    int rc = zcl_spawn_capture_merged_in_dir_observed(argv, f->base, output, sizeof(output), WI_DEADLINE_MS, &timeout);
    bool ok = !timeout && rc != 0 && strstr(output, "APP_PROFILE_REFUSED");
    return wi_write(saved.path, saved.bytes, saved.length, 0600) && ok;
}

static bool wi_profile_unsafe(const struct wi_release *f, const char *profile)
{
    char output[8192], state[PATH_MAX]; struct stat st;
    if (snprintf(state, sizeof(state), "%s/state/z23", f->base) >= (int)sizeof(state) || chmod(profile, 0777)) return false;
    bool ok = wi_profile_install(f, profile, output, sizeof(output), false) &&
        strstr(output, "app profile selection refused") && lstat(state, &st) != 0 && errno == ENOENT &&
        lstat(profile, &st) == 0 && (st.st_mode & 0777) == 0777;
    return chmod(profile, 0700) == 0 && ok;
}

static bool wi_profile_no_setting(const struct wi_release *f)
{
    char path[PATH_MAX]; struct stat st;
    return snprintf(path, sizeof(path), "%s/state/z23", f->base) < (int)sizeof(path) &&
        lstat(path, &st) != 0 && errno == ENOENT;
}

static bool wi_profile_legacy_unsafe(const struct wi_release *f)
{
    char linkpath[PATH_MAX], target[PATH_MAX], output[8192];
    if (snprintf(linkpath, sizeof(linkpath), "%s/state/z23", f->base) >= (int)sizeof(linkpath) ||
        snprintf(target, sizeof(target), "%s/data", f->base) >= (int)sizeof(target) || symlink(target, linkpath)) return false;
    bool ok = wi_profile_install(f, NULL, output, sizeof(output), false) &&
        strstr(output, "cannot validate an existing or unsafe app profile");
    return unlink(linkpath) == 0 && ok;
}

static bool wi_profile_current_unsafe(const struct wi_release *f, const char *profile)
{
    char exe[PATH_MAX], output[4096]; bool timeout = false;
    if (!realpath(WI_EXE, exe) || chmod(profile, 0777)) return false;
    const char *argv[] = {exe, "ops", "host", "app-profile", "get", "--json", NULL};
    int rc = zcl_spawn_capture_merged_in_dir_observed(argv, f->base, output, sizeof(output), WI_DEADLINE_MS, &timeout);
    struct stat st;
    bool ok = !timeout && rc != 0 && strstr(output, "APP_PROFILE_REFUSED") &&
        lstat(profile, &st) == 0 && (st.st_mode & 0777) == 0777;
    return chmod(profile, 0700) == 0 && ok;
}

static bool wi_profile_default_untouched(const struct wi_release *f)
{
    char path[PATH_MAX]; struct stat st;
    return snprintf(path, sizeof(path), "%s/home/.local/share", f->base) < (int)sizeof(path) &&
        lstat(path, &st) != 0 && errno == ENOENT;
}

static bool wi_profile_target_unchanged(const char *target)
{
    char bytes[8] = {0}; FILE *in = fopen(target, "rb");
    if (!in) return false;
    size_t n = fread(bytes, 1, sizeof(bytes), in); bool ok = !ferror(in);
    ok = fclose(in) == 0 && ok;
    return ok && n == 4 && !memcmp(bytes, "safe", 4);
}


static bool wi_profile_record_symlink(const struct wi_release *f, const char *profile)
{
    char exe[PATH_MAX], target[PATH_MAX], output[4096]; bool timeout = false; struct wi_profile_record saved;
    (void)profile;
    if (!realpath(WI_EXE, exe) || !wi_profile_record_read(f, &saved) ||
        snprintf(target, sizeof(target), "%s/profile-target", f->base) >= (int)sizeof(target) || !wi_write(target, "safe", 4, 0600) ||
        unlink(saved.path) || symlink(target, saved.path)) return false;
    const char *argv[] = {exe, "ops", "host", "app-profile", "get", "--json", NULL};
    int rc = zcl_spawn_capture_merged_in_dir_observed(argv, f->base, output, sizeof(output), WI_DEADLINE_MS, &timeout);
    bool ok = !timeout && rc != 0 && strstr(output, "APP_PROFILE_REFUSED") && wi_profile_target_unchanged(target);
    return unlink(saved.path) == 0 && wi_write(saved.path, saved.bytes, saved.length, 0600) && ok;
}

static bool wi_profile_duplicate(const struct wi_release *f, const char *profile)
{
    char option[PATH_MAX + 32], output[4096]; bool timeout = false;
    if (snprintf(option, sizeof(option), "--app-datadir=%s", profile) >= (int)sizeof(option)) return false;
    const char *argv[] = {"bash", f->script, "--apps", option, option, NULL};
    int rc = zcl_spawn_capture_merged_in_dir_observed(argv, f->base, output, sizeof(output), WI_DEADLINE_MS, &timeout);
    return !timeout && rc != 0 && strstr(output, "may be supplied once") && wi_profile_no_setting(f);
}

static bool wi_profile_legacy_case(struct wi_release *f, const char *profile)
{
    char output[8192];
    return wi_profile_legacy(f) && wi_profile_install(f, NULL, output, sizeof(output), true) &&
        strstr(output, "app open tasks --datadir=") && wi_profile_no_setting(f) && wi_profile_legacy_unsafe(f) &&
        wi_profile_install(f, profile, output, sizeof(output), false) && strstr(output, "this release cannot select an app profile") && wi_profile_no_setting(f);
}

static bool wi_profile_wrong_target(const struct wi_release *f, const char *profile, const char *token)
{
    char exe[PATH_MAX], path[PATH_MAX + 16], plan[80], record[PATH_MAX], output[4096];
    bool timeout = false; struct stat st;
    if (!realpath(WI_EXE, exe) || snprintf(path, sizeof(path), "--path=%s", profile) >= (int)sizeof(path) ||
        snprintf(plan, sizeof(plan), "--plan_id=%s", token) >= (int)sizeof(plan) ||
        snprintf(record, sizeof(record), "%s/state/z23/apps/desktop-profile", f->base) >= (int)sizeof(record)) return false;
    const char *argv[] = {exe, "ops", "host", "app-profile", "set", path, plan, "--json", NULL};
    int rc = zcl_spawn_capture_merged_in_dir_observed(argv, f->base, output, sizeof(output), WI_DEADLINE_MS, &timeout);
    return !timeout && rc != 0 && strstr(output, "APP_PROFILE_REFUSED") && lstat(record, &st) != 0 && errno == ENOENT;
}

static bool wi_profile_target_swapped(const struct wi_release *f, const char *profile)
{
    char token[65], held[PATH_MAX], exe[PATH_MAX], path[PATH_MAX + 16], plan[80], output[4096]; bool timeout = false;
    if (!wi_profile_token(f, profile, token) || !realpath(WI_EXE, exe) ||
        snprintf(held, sizeof(held), "%s/held-profile", f->base) >= (int)sizeof(held) ||
        snprintf(path, sizeof(path), "--path=%s", profile) >= (int)sizeof(path) ||
        snprintf(plan, sizeof(plan), "--plan_id=%s", token) >= (int)sizeof(plan) || rename(profile, held)) return false;
    bool made = mkdir(profile, 0700) == 0;
    const char *argv[] = {exe, "ops", "host", "app-profile", "set", path, plan, "--json", NULL};
    int rc = made ? zcl_spawn_capture_merged_in_dir_observed(argv, f->base, output, sizeof(output), WI_DEADLINE_MS, &timeout) : 0;
    bool refused = made && !timeout && rc != 0 && strstr(output, "APP_PROFILE_REFUSED");
    bool removed = !made || rmdir(profile) == 0;
    return rename(held, profile) == 0 && removed && refused;
}

static bool wi_profile_replaced(const struct wi_release *f, const char *profile)
{
    char held[PATH_MAX], output[8192];
    if (snprintf(held, sizeof(held), "%s/held-profile", f->base) >= (int)sizeof(held) || rename(profile, held)) return false;
    bool made = mkdir(profile, 0700) == 0;
    bool refused = made && wi_profile_install(f, NULL, output, sizeof(output), false) && strstr(output, "app profile lookup refused");
    bool recovered = refused && wi_profile_install(f, profile, output, sizeof(output), true) &&
        wi_profile_install(f, NULL, output, sizeof(output), true) && strstr(output, "chosen\\ \\'\\ profile");
    return rmdir(held) == 0 && recovered;
}

static bool wi_profile_library_arguments(const struct wi_release *f, const char *exe);
static bool wi_profile_bad_arguments(const struct wi_release *f, const char *exe)
{
    char out[4096]; bool timeout = false;
    const char *invalid[] = {exe, "app", "receive", "--file=/absent.z23share", "--app_profile=other", "--json", NULL};
    int rc = zcl_spawn_capture_merged_in_dir_observed(invalid, f->base, out, sizeof(out), WI_DEADLINE_MS, &timeout);
    if (timeout || rc == 0 || !strstr(out, "BAD_INPUT") || !strstr(out, "app_profile=desktop")) { fprintf(stderr, "profile invalid rc=%d: %s\n", rc, out); return false; }
    const char *conflict[] = {exe, "app", "receive", "--file=/absent.z23share", "--app_profile=desktop", "--datadir=/private", "--json", NULL};
    rc = zcl_spawn_capture_merged_in_dir_observed(conflict, f->base, out, sizeof(out), WI_DEADLINE_MS, &timeout);
    if (timeout || rc == 0 || !strstr(out, "BAD_INPUT") || !strstr(out, "not both")) { fprintf(stderr, "profile conflict rc=%d: %s\n", rc, out); return false; }
    return wi_profile_library_arguments(f, exe);
}
/* app library: a bad value names the accepted value; both keys keep "not both". */
static bool wi_profile_library_arguments(const struct wi_release *f, const char *exe)
{
    static const struct { const char *arg, *arg2, *code, *want, *unwanted; } k[] = {
        {"--app_profile=bogus", NULL, "BAD_INPUT", "must be desktop", "not both"},
        {"--app_profile=", NULL, "INVALID_INPUT", "input key 'app_profile'", "not both"},
        {"--app_profile=desktop", "--datadir=/private", "BAD_INPUT", "not both", "must be desktop"},
    };
    for (size_t i = 0; i < sizeof k / sizeof k[0]; i++) {
        char out[4096]; bool timeout = false;
        const char *argv[] = {exe, "app", "library", k[i].arg, "--json", k[i].arg2, NULL};
        int rc = zcl_spawn_capture_merged_in_dir_observed(argv, f->base, out, sizeof(out), WI_DEADLINE_MS, &timeout);
        if (timeout || rc == 0 || !strstr(out, k[i].code) || !strstr(out, k[i].want) || strstr(out, k[i].unwanted)) {
            fprintf(stderr, "library profile case %zu rc=%d: %s\n", i, rc, out); return false;
        }
    }
    return true;
}
static bool wi_profile_stale_commands(const struct wi_release *f, const char *exe)
{
    char out[4096]; bool timeout = false;
    const char *library[] = {exe, "app", "library", "--app_profile=desktop", "--json", NULL};
    int rc = zcl_spawn_capture_merged_in_dir_observed(library, f->base, out, sizeof(out), WI_DEADLINE_MS, &timeout);
    bool ok = !timeout && rc != 0 && strstr(out, "APP_PROFILE_REFUSED");
    if (!ok) fprintf(stderr, "profile stale library rc=%d: %s\n", rc, out);
    const char *receive[] = {exe, "app", "receive", "--file=/absent.z23share", "--app_profile=desktop", "--json", NULL};
    rc = zcl_spawn_capture_merged_in_dir_observed(receive, f->base, out, sizeof(out), WI_DEADLINE_MS, &timeout);
    if (timeout || rc == 0 || !strstr(out, "APP_PROFILE_REFUSED")) { fprintf(stderr, "profile stale receive rc=%d: %s\n", rc, out); ok = false; }
    return ok;
}
static bool wi_profile_resolve_case(const struct wi_release *f, const char *profile)
{
    char path[APP_LAUNCH_PATH_MAX], exe[PATH_MAX], moved[PATH_MAX]; bool selected = false;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_profile.v1");
    bool ok = app_desktop_profile_resolve(path, sizeof(path), &selected, &reply) && selected && !strcmp(path, profile);
    zcl_command_reply_free(&reply);
    if (!ok || !realpath(WI_EXE, exe) || !wi_profile_bad_arguments(f, exe) ||
        snprintf(moved, sizeof(moved), "%s/moved-profile", f->base) >= (int)sizeof(moved) || rename(profile, moved)) return false;
    ok = wi_profile_stale_commands(f, exe);
    return rename(moved, profile) == 0 && ok;
}
static bool wi_profile_first_install(struct wi_release *f, const char *profile, char token[65])
{
    char output[8192];
    return wi_profile_duplicate(f, profile) && wi_profile_unsafe(f, profile) && wi_profile_prepare_stale(f, token) &&
        wi_profile_no_setting(f) && wi_profile_wrong_target(f, profile, token) && wi_profile_target_swapped(f, profile) && wi_profile_install(f, profile, output, sizeof(output), true) &&
        strstr(output, "chosen\\ \\'\\ profile") && wi_profile_default_untouched(f) && wi_profile_resolve_case(f, profile);
}

static bool wi_profile_reinstall(struct wi_release *f, const char *profile, const char *token)
{
    char output[8192];
    if (!wi_profile_install(f, NULL, output, sizeof(output), true) || !strstr(output, "chosen\\ \\'\\ profile") ||
        !wi_profile_desktops(f) || !wi_profile_stale(f, token) || !wi_profile_current_unsafe(f, profile) ||
        !wi_profile_corrupt(f, profile) || !wi_profile_record_symlink(f, profile) || !wi_profile_replaced(f, profile)) return false;
    return wi_profile_install(f, NULL, output, sizeof(output), true) && strstr(output, "chosen\\ \\'\\ profile") &&
        wi_profile_legacy(f) && wi_profile_install(f, NULL, output, sizeof(output), false) &&
        strstr(output, "cannot validate an existing or unsafe app profile");
}


static bool wi_profile_case(bool legacy_first)
{
    struct wi_release f = {0};
    const char *keys[] = {"HOME", "XDG_DATA_HOME", "Z23_INSTALL_PREFIX", "Z23_SKIP_SYSTEMD", "Z23_INSTALL_DOCS_DIR", "PATH", "Z23_INSTALL_TEST_PLATFORM", "XDG_STATE_HOME"};
    char *saved[8] = {0}, profile[PATH_MAX], token[65];
    for (size_t i = 0; i < 8; ++i) { const char *v = getenv(keys[i]); if (v && !(saved[i] = strdup(v))) return false; }
    bool ok = wi_apps_release(&f, true) && wi_apps_manifest(&f, true) && wi_apps_env(&f, keys) &&
        snprintf(profile, sizeof(profile), "%s/chosen ' profile", f.base) < (int)sizeof(profile) && mkdir(profile, 0700) == 0;
    if (ok) ok = legacy_first ? wi_profile_legacy_case(&f, profile) :
        wi_profile_first_install(&f, profile, token) && wi_profile_reinstall(&f, profile, token);
    for (size_t i = 0; i < 8; ++i) wi_restore_env(keys[i], saved[i]);
    if (f.base[0]) TEST_DISCARD(test_rm_rf_recursive(f.base));
    return ok;
}


static bool wi_macos_manifest_base(struct wi_release *f, FILE *out)
{
    static const char *const base[] = {"AGENT_CARD.md", "z23", "zclassic23", "z23-acme", "zclassic23-acme", "z23-package-verify", "zclassic23-package-verify", "installed-source.json", "source.bundle", "manifest.wire", "recipe.wire", "app-build.wire", "z23-skycombat"};
    char path[PATH_MAX], hash[65];
    for (size_t i = 0; i < sizeof(base) / sizeof(base[0]); ++i) {
        int n = snprintf(path, sizeof(path), "%s/%s", f->release, base[i]);
        if (n <= 0 || (size_t)n >= sizeof(path) || !wi_sha256(path, hash) || fprintf(out, "%s  %s\n", hash, base[i]) <= 0) return false;
    }
    return true;
}

static bool wi_macos_members(struct wi_release *f, bool modern)
{
    static const char launcher[] = "#!/bin/sh\n[ \"$1\" != --supports-desktop-profile ] || exit 2\nprintf 'register\\n' >>\"$HOME/launcher-called\"\n";
    static const char modern_launcher[] = "#!/bin/sh\n[ \"$1\" != --supports-desktop-profile ] || exit 0\nprintf 'register\\n' >>\"$HOME/launcher-called\"\n";
    static const char *const names[] = {"z23-app-macos", "Z23Apps-Info.plist"};
    char path[PATH_MAX], hash[65];
    FILE *out = fopen(f->manifest, "wb"); if (!out) return false;
    bool ok = wi_macos_manifest_base(f, out);
    for (size_t i = 0; ok && i < 2; ++i) {
        const char *bytes = i ? "fixture\n" : modern ? modern_launcher : launcher;
        int n = snprintf(path, sizeof(path), "%s/%s", f->release, names[i]);
        ok = n > 0 && (size_t)n < sizeof(path) && wi_write(path, bytes, strlen(bytes), i ? 0600 : 0700) &&
            wi_sha256(path, hash) && fprintf(out, "%s  %s\n", hash, names[i]) > 0;
    }
    return fclose(out) == 0 && ok && wi_sha256(f->manifest, f->pin);
}

static bool wi_profile_apply(const struct wi_release *f, const char *profile)
{
    char exe[PATH_MAX], token[65], path[PATH_MAX + 16], plan[80], output[4096]; bool timeout = false;
    if (!wi_profile_token(f, profile, token) || !realpath(WI_EXE, exe) ||
        snprintf(path, sizeof(path), "--path=%s", profile) >= (int)sizeof(path) ||
        snprintf(plan, sizeof(plan), "--plan_id=%s", token) >= (int)sizeof(plan)) return false;
    const char *argv[] = {exe, "ops", "host", "app-profile", "set", path, plan, "--json", NULL};
    int rc = zcl_spawn_capture_merged_in_dir_observed(argv, f->base, output, sizeof(output), WI_DEADLINE_MS, &timeout);
    return !timeout && rc == 0 && strstr(output, "\"selected\":true");
}

static bool wi_macos_refuse_custom(struct wi_release *f, const char *profile)
{
    char output[8192], prefix[PATH_MAX];
    return snprintf(prefix, sizeof(prefix), "%s/prefix space", f->base) < (int)sizeof(prefix) &&
        wi_profile_install(f, profile, output, sizeof(output), false) &&
        strstr(output, "this macOS launcher cannot use the saved custom app profile") &&
        wi_profile_no_setting(f) && access(prefix, F_OK) != 0 && errno == ENOENT;
}

static bool wi_macos_saved_refused(struct wi_release *f, const char *profile)
{
    char output[8192], exe[PATH_MAX], marker[PATH_MAX], before[65], after[65], marker_before[65], marker_after[65];
    return snprintf(exe, sizeof(exe), "%s/prefix space/bin/z23", f->base) < (int)sizeof(exe) &&
        snprintf(marker, sizeof(marker), "%s/launcher-called", getenv("HOME")) < (int)sizeof(marker) &&
        wi_sha256(exe, before) && wi_sha256(marker, marker_before) && wi_profile_apply(f, profile) &&
        wi_profile_install(f, NULL, output, sizeof(output), false) &&
        strstr(output, "this macOS launcher cannot use the saved custom app profile") &&
        wi_sha256(exe, after) && !strcmp(before, after) && wi_sha256(marker, marker_after) && !strcmp(marker_before, marker_after);
}

static bool wi_macos_profile_case(void)
{
    struct wi_release f = {0};
    const char *keys[] = {"HOME", "XDG_DATA_HOME", "Z23_INSTALL_PREFIX", "Z23_SKIP_SYSTEMD", "Z23_INSTALL_DOCS_DIR", "PATH", "Z23_INSTALL_TEST_PLATFORM", "XDG_STATE_HOME"};
    char *saved[8] = {0}, profile[PATH_MAX], output[8192];
    for (size_t i = 0; i < 8; ++i) { const char *v = getenv(keys[i]); if (v && !(saved[i] = strdup(v))) return false; }
    bool ok = wi_apps_release(&f, false) && wi_macos_members(&f, false) && wi_apps_env(&f, keys) && setenv(keys[6], "Darwin", 1) == 0 &&
        snprintf(profile, sizeof(profile), "%s/chosen profile", f.base) < (int)sizeof(profile) && mkdir(profile, 0700) == 0 &&
        wi_macos_refuse_custom(&f, profile) && wi_profile_install(&f, NULL, output, sizeof(output), true) &&
        strstr(output, "app open skycombat --datadir=") && wi_macos_saved_refused(&f, profile);
    for (size_t i = 0; i < 8; ++i) wi_restore_env(keys[i], saved[i]);
    if (f.base[0]) TEST_DISCARD(test_rm_rf_recursive(f.base));
    return ok;
}

static bool wi_macos_schema_runtime(struct wi_release *f, bool receive)
{
    char exe[PATH_MAX], path[PATH_MAX], text[PATH_MAX + 1024];
    if (!realpath(WI_EXE, exe) || strchr(exe, '\'')) return false;
    int n = snprintf(text, sizeof(text),
        "#!/bin/sh\nif [ \"$1 $2 $3\" = 'discover schema app.library' ]; then echo '{\"allowed_keys\":\"extra,datadir,app_profile,more\"}'; exit 0; fi\n"
        "if [ \"$1 $2 $3\" = 'discover schema app.receive' ]; then echo '{\"allowed_keys\":\"file,%s,preview\"}'; exit 0; fi\n"
        "if [ \"$1\" = -version ]; then echo 'tor: full'; exit 0; fi\nexec '%s' \"$@\"\n", receive ? "app_profile" : "datadir", exe);
    if (n <= 0 || (size_t)n >= sizeof(text)) return false;
    static const char *const names[] = {"z23", "zclassic23"};
    for (size_t i = 0; i < 2; ++i) {
        n = snprintf(path, sizeof(path), "%s/%s", f->release, names[i]);
        if (n <= 0 || (size_t)n >= sizeof(path) || !wi_write(path, text, strlen(text), 0700)) return false;
    }
    return wi_macos_members(f, true);
}
static bool wi_macos_modern_install(struct wi_release *f, const char *profile)
{
    char output[8192];
    return wi_macos_schema_runtime(f, false) && wi_profile_install(f, profile, output, sizeof(output), false) &&
        strstr(output, "this runtime cannot use the desktop app profile") && wi_profile_no_setting(f) &&
        wi_macos_schema_runtime(f, true) && wi_profile_install(f, profile, output, sizeof(output), true) &&
        wi_profile_install(f, NULL, output, sizeof(output), true) && strstr(output, "chosen\\ profile");
}
static bool wi_macos_modern_case(void)
{
    struct wi_release f = {0};
    const char *keys[] = {"HOME", "XDG_DATA_HOME", "Z23_INSTALL_PREFIX", "Z23_SKIP_SYSTEMD", "Z23_INSTALL_DOCS_DIR", "PATH", "Z23_INSTALL_TEST_PLATFORM", "XDG_STATE_HOME"};
    char *saved[8] = {0}, profile[PATH_MAX];
    for (size_t i = 0; i < 8; ++i) { const char *v = getenv(keys[i]); if (v && !(saved[i] = strdup(v))) return false; }
    bool ok = wi_apps_release(&f, false) && wi_apps_env(&f, keys) && setenv(keys[6], "Darwin", 1) == 0 &&
        snprintf(profile, sizeof(profile), "%s/chosen profile", f.base) < (int)sizeof(profile) && mkdir(profile, 0700) == 0 &&
        wi_macos_modern_install(&f, profile);
    for (size_t i = 0; i < 8; ++i) wi_restore_env(keys[i], saved[i]);
    if (f.base[0]) TEST_DISCARD(test_rm_rf_recursive(f.base));
    return ok;
}

static int wi_apps_guidance(void)
{
    int failures = 0;
    TEST("verified app payload chooses matching launch guidance and desktop entry") {
        ASSERT(wi_apps_case(true));
        ASSERT(wi_apps_case(false));
        ASSERT(wi_apps_symlink_refused());
        ASSERT(wi_profile_case(false));
        ASSERT(wi_profile_case(true));
        ASSERT(wi_macos_profile_case());
        ASSERT(wi_macos_modern_case());
        PASS();
    } _test_next:;
    return failures;
}


int test_wiki_docs_install(void)
{
    int failures = 0;
    failures += wi_layout("linux", "bin/z23");
    failures += wi_layout("macos", "lib/z23/generations/" WI_GEN "/z23");
    failures += wi_standalone_release();
    failures += wi_apps_guidance();
    return failures;
}
