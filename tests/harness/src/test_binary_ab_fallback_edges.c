/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sub-test of the `binary_ab_fallback` group (dispatched from
 * test_binary_ab_fallback.c, which owns that group's entry point and its
 * scratch directory). The node-side A/B code decides what becomes the
 * last-good slot, and the launcher falls back to that slot after a failed
 * upgrade; a wrong byte, a truncated path or a stray staging file in it is
 * the failure that matters. The main file drives the launcher matrix and the
 * happy paths; this one pins what a mutation sweep measured as unguarded:
 *
 *  1. the self-respawn streak increment, refused on a corrupt or overflowing
 *     streak, with the file left as found;
 *  2. promotion at every copy boundary (the 64 KiB chunk edges), the
 *     refusal of a non-executable or missing source, no staging file left
 *     behind by a failed promotion, and the next promotion succeeding;
 *  3. the slot path length limit: a last-good or streak path of exactly 1024
 *     bytes is refused and NOTHING is created under a truncated name, while
 *     one byte shorter is accepted;
 *  4. the three env wrappers: unset or empty slots dir is a no-op, the
 *     fallback flag is exactly "1", a fallback ready never touches the
 *     last-good slot, and the blocker carries its id, owner, class and the
 *     launcher threshold in its reason;
 *  5. the log line each refusal leaves, since the operator reads those.
 *
 * Fixtures are a private subdirectory of the group's temp dir. The running
 * test executable is the promoted image in the env cases; it is compared to
 * the slot byte for byte. */

#include "test/test_core.h"
#include "services/binary_ab_fallback.h"
#include "base/log_level.h"
#include "util/blocker.h"

#if !defined(_WIN32)

#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define AE_CHECK(name, expr) do { \
    printf("ab edges: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

#define AE_COPY_CHUNK (64 * 1024)

/* ── helpers ──────────────────────────────────────────────────────── */

static bool ae_write(const char *path, const uint8_t *data, size_t n,
                     mode_t mode)
{
    FILE *fp = fopen(path, "wb");
    if (!fp) return false;
    bool ok = n == 0 || fwrite(data, 1, n, fp) == n;
    ok = fclose(fp) == 0 && ok;
    return ok && chmod(path, mode) == 0;
}

static bool ae_write_str(const char *path, const char *s, mode_t mode)
{
    return ae_write(path, (const uint8_t *)s, strlen(s), mode);
}

static bool ae_text_is(const char *path, const char *want)
{
    char buf[128] = {0};
    FILE *fp = fopen(path, "rb");
    if (!fp) return false;
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    return strcmp(buf, want) == 0;
}

static bool ae_files_equal(const char *a, const char *b)
{
    FILE *fa = fopen(a, "rb");
    FILE *fb = fopen(b, "rb");
    bool same = fa && fb;
    static unsigned char ba[8192], bb[8192];
    while (same) {
        size_t na = fread(ba, 1, sizeof(ba), fa);
        size_t nb = fread(bb, 1, sizeof(bb), fb);
        same = na == nb && memcmp(ba, bb, na) == 0;
        if (na == 0 || nb == 0) break;
    }
    if (fa) fclose(fa);
    if (fb) fclose(fb);
    return same;
}

/* Entries in `dir` other than . and .., and how many carry ".tmp.". */
static void ae_scan(const char *dir, int *entries, int *staging)
{
    *entries = 0;
    *staging = 0;
    DIR *d = opendir(dir);
    if (!d) { *entries = -1; return; }
    for (struct dirent *e = readdir(d); e; e = readdir(d)) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        (*entries)++;
        if (strstr(e->d_name, ".tmp.")) (*staging)++;
    }
    closedir(d);
}

static void ae_pattern(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        p[i] = (uint8_t)(i * 31u + i / 251u + 7u);
}

/* Create nested directories under `base` until the path is `total` bytes. */
static bool ae_nested_dir(const char *base, size_t total, char *out,
                          size_t cap)
{
    snprintf(out, cap, "%s", base);
    while (strlen(out) < total) {
        size_t remaining = total - strlen(out);
        size_t name = remaining - 1;
        if (remaining < 2 || strlen(out) + 1 + 200 >= cap) return false;
        if (name > 200) {
            name = 200;
            if (remaining - 201 == 1) name = 199;
        }
        size_t at = strlen(out);
        out[at] = '/';
        memset(out + at + 1, 'n', name);
        out[at + 1 + name] = '\0';
        if (mkdir(out, 0700) != 0) return false;
    }
    return strlen(out) == total;
}

static void ae_rm_nested(const char *base, char *path)
{
    while (strlen(path) > strlen(base)) {
        (void)rmdir(path);
        char *slash = strrchr(path, '/');
        if (!slash) break;
        *slash = '\0';
    }
}

/* ── stderr capture (the operator's log lines) ───────────────────── */

static char g_ae_log[65536];
static const char *g_ae_cap_dir;

static bool ae_capture(void (*fn)(void))
{
    char path[1100];
    snprintf(path, sizeof(path), "%s/capture.log", g_ae_cap_dir);
    g_ae_log[0] = '\0';
    fflush(stderr);
    int saved = dup(STDERR_FILENO);
    FILE *capf = saved >= 0 ? fopen(path, "w+") : NULL;
    if (!capf) {
        if (saved >= 0) close(saved);
        return false;
    }
    enum zcl_log_level level = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_ALL);
    dup2(fileno(capf), STDERR_FILENO);
    fn();
    fflush(stderr);
    dup2(saved, STDERR_FILENO);
    close(saved);
    zcl_log_level_set(level);
    long sz = ftell(capf);
    if (sz > 0) {
        rewind(capf);
        size_t want = (size_t)sz < sizeof(g_ae_log) - 1
                          ? (size_t)sz : sizeof(g_ae_log) - 1;
        size_t got = fread(g_ae_log, 1, want, capf);
        g_ae_log[got] = '\0';
    }
    fclose(capf);
    unlink(path);
    return true;
}

static bool ae_logged(const char *needle)
{
    return strstr(g_ae_log, needle) != NULL;
}

/* ── env save / set ──────────────────────────────────────────────── */

static void ae_env(const char *name, const char *value)
{
    if (value) setenv(name, value, 1);
    else unsetenv(name);
}

struct ae_env_save {
    char slots[1200];
    char fb[16];
    bool had_slots;
    bool had_fb;
};

static void ae_env_save(struct ae_env_save *s)
{
    const char *a = getenv(BINARY_AB_ENV_SLOTS_DIR);
    const char *b = getenv(BINARY_AB_ENV_FALLBACK);
    s->had_slots = a != NULL;
    s->had_fb = b != NULL;
    snprintf(s->slots, sizeof(s->slots), "%s", a ? a : "");
    snprintf(s->fb, sizeof(s->fb), "%s", b ? b : "");
}

static void ae_env_restore(const struct ae_env_save *s)
{
    ae_env(BINARY_AB_ENV_SLOTS_DIR, s->had_slots ? s->slots : NULL);
    ae_env(BINARY_AB_ENV_FALLBACK, s->had_fb ? s->fb : NULL);
}

/* ── 1. streak increment ─────────────────────────────────────────── */

static char g_ae_arg[1200];

static void ae_do_note(void)    { (void)binary_ab_note_self_respawn_exit(g_ae_arg); }
static void ae_do_reset(void)   { (void)binary_ab_reset_streak(g_ae_arg); }

static int ae_streak_increment(const char *mut, const char *streak)
{
    int failures = 0;
    AE_CHECK("note_self_respawn_exit refuses NULL and empty paths",
             !binary_ab_note_self_respawn_exit(NULL) &&
             !binary_ab_note_self_respawn_exit(""));
    AE_CHECK("seed streak 2", ae_write_str(streak, "2\n", 0600));
    snprintf(g_ae_arg, sizeof(g_ae_arg), "%s", streak);
    AE_CHECK("increment logs and succeeds", ae_capture(ae_do_note) &&
             ae_logged("boot-failure streak incremented (self-respawn exit"));
    AE_CHECK("2 became 3", ae_text_is(streak, "3\n"));
    AE_CHECK("increment returns true",
             binary_ab_note_self_respawn_exit(streak) &&
             ae_text_is(streak, "4\n"));

    AE_CHECK("seed a corrupt streak", ae_write_str(streak, "garbage\n", 0600));
    AE_CHECK("a corrupt streak is refused, with the reason logged",
             ae_capture(ae_do_note) && ae_logged("note_self_respawn_exit(") &&
             ae_logged("refused"));
    AE_CHECK("refusal returns false and leaves the evidence",
             !binary_ab_note_self_respawn_exit(streak) &&
             ae_text_is(streak, "garbage\n"));
    AE_CHECK("seed an overflowing streak",
             ae_write_str(streak, "4294967295\n", 0600));
    AE_CHECK("UINT32_MAX is refused, not wrapped to 0",
             !binary_ab_note_self_respawn_exit(streak) &&
             ae_text_is(streak, "4294967295\n"));

    AE_CHECK("reset to 0 clears it", binary_ab_reset_streak(streak) &&
             ae_text_is(streak, "0\n"));
    AE_CHECK("reset logs the path it cleared", ae_capture(ae_do_reset) &&
             ae_logged("boot-failure streak reset to 0"));
    (void)mut;
    return failures;
}

static int ae_streak_reset_failures(const char *mut)
{
    int failures = 0;
    char missing[1200];
    snprintf(missing, sizeof(missing), "%s/no-such-dir/streak", mut);
    snprintf(g_ae_arg, sizeof(g_ae_arg), "%s", missing);
    AE_CHECK("reset into a missing directory fails and says why",
             !binary_ab_reset_streak(missing) && ae_capture(ae_do_reset) &&
             ae_logged("reset_streak(") && ae_logged("failed"));
    AE_CHECK("reset with an empty path logs the empty-path line",
             (snprintf(g_ae_arg, sizeof(g_ae_arg), "%s", ""), true) &&
             ae_capture(ae_do_reset) &&
             ae_logged("reset_streak: empty streak_file path"));
    AE_CHECK("note with an empty path logs the empty-path line",
             ae_capture(ae_do_note) &&
             ae_logged("note_self_respawn_exit: empty streak_file path"));
    return failures;
}

/* ── 2. promotion at copy boundaries ─────────────────────────────── */

static int ae_promote_size(const char *mut, const char *cur,
                           const char *lastgood, size_t n)
{
    int failures = 0;
    static uint8_t data[3 * AE_COPY_CHUNK + 5];
    ae_pattern(data, n);
    char label[96];
    snprintf(label, sizeof(label), "promote %zu bytes is byte-exact", n);
    struct stat st;
    bool wrote = ae_write(cur, data, n, 0755);
    bool promoted = wrote && binary_ab_promote(mut, cur);
    AE_CHECK(label, promoted && ae_files_equal(cur, lastgood) &&
             stat(lastgood, &st) == 0 && (size_t)st.st_size == n &&
             (st.st_mode & S_IXUSR));
    int entries, staging;
    ae_scan(mut, &entries, &staging);
    AE_CHECK("no staging file is left after a successful promote",
             staging == 0);
    return failures;
}

static int ae_promote_boundaries(const char *mut, const char *cur,
                                 const char *lastgood)
{
    int failures = 0;
    const size_t sizes[] = {
        1, AE_COPY_CHUNK - 1, AE_COPY_CHUNK, AE_COPY_CHUNK + 1,
        2 * AE_COPY_CHUNK, 3 * AE_COPY_CHUNK + 5,
    };
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
        failures += ae_promote_size(mut, cur, lastgood, sizes[i]);
    return failures;
}

static int ae_promote_refusals(const char *mut, const char *cur,
                               const char *lastgood)
{
    int failures = 0;
    AE_CHECK("seed a good last-good", ae_write_str(lastgood, "GOOD", 0755));
    AE_CHECK("a non-executable current is refused",
             ae_write_str(cur, "NOT-EXEC", 0644) &&
             !binary_ab_promote(mut, cur));
    AE_CHECK("a missing current is refused",
             unlink(cur) == 0 && !binary_ab_promote(mut, cur));
    AE_CHECK("a directory as current is refused",
             !binary_ab_promote(mut, mut));
    AE_CHECK("a missing slots dir is refused, even for a good current",
             ae_write_str(cur, "CANDIDATE", 0755) &&
             !binary_ab_promote("/nonexistent-ab-slots-dir", cur));
    AE_CHECK("every refusal left the committed last-good alone",
             ae_text_is(lastgood, "GOOD"));
    int entries, staging;
    ae_scan(mut, &entries, &staging);
    AE_CHECK("no staging file is left after a refused promote", staging == 0);
    return failures;
}

/* A zero-length executable must not replace a good last-good. */
static int ae_promote_empty_source(const char *mut, const char *cur,
                                   const char *lastgood)
{
    int failures = 0;
    AE_CHECK("seed last-good and an empty executable",
             ae_write_str(lastgood, "KEEP-ME", 0755) &&
             ae_write(cur, (const uint8_t *)"", 0, 0755));
    AE_CHECK("an empty current is refused", !binary_ab_promote(mut, cur));
    AE_CHECK("the refusal left last-good byte-identical",
             ae_text_is(lastgood, "KEEP-ME"));
    int entries, staging;
    ae_scan(mut, &entries, &staging);
    AE_CHECK("an empty-source refusal leaves no staging file", staging == 0);
    return failures;
}

static int ae_promote_after_injected_failure(const char *mut, const char *cur,
                                             const char *lastgood)
{
    int failures = 0;
    AE_CHECK("seed last-good and candidate",
             ae_write_str(lastgood, "OLD", 0755) &&
             ae_write_str(cur, "NEW-CANDIDATE", 0755));
    binary_ab_test_fail_before_promote_rename_once();
    AE_CHECK("injected failure: promote reports false",
             !binary_ab_promote(mut, cur) && ae_text_is(lastgood, "OLD"));
    int entries, staging;
    ae_scan(mut, &entries, &staging);
    AE_CHECK("injected failure leaves no staging file", staging == 0);
    AE_CHECK("the injection is one-shot: the next promote lands",
             binary_ab_promote(mut, cur) &&
             ae_text_is(lastgood, "NEW-CANDIDATE"));
    return failures;
}

/* A one-character relative current path (cwd is the slots dir): the empty-string
 * guard must test the first byte, not the second. */
static int ae_promote_short_relative(const char *mut)
{
    int failures = 0;
    int cwd = open(".", O_RDONLY | O_DIRECTORY);
    bool moved = cwd >= 0 && chdir(mut) == 0;
    AE_CHECK("enter the fixture directory", moved);
    if (moved) {
        AE_CHECK("seed one-character candidate x",
                 ae_write_str("x", "ONE-CHAR", 0755));
        AE_CHECK("promote(slots, \"x\") accepts a one-character current",
                 binary_ab_promote(mut, "x") &&
                 ae_text_is(BINARY_AB_LASTGOOD_BASENAME, "ONE-CHAR"));
        AE_CHECK("on_ready(slots, \"x\") accepts a one-character current",
                 ae_write_str(BINARY_AB_STREAK_BASENAME, "3\n", 0600) &&
                 binary_ab_on_ready(mut, "x", false) &&
                 ae_text_is(BINARY_AB_STREAK_BASENAME, "0\n"));
        unlink("x");
        unlink(BINARY_AB_LASTGOOD_BASENAME);
        unlink(BINARY_AB_STREAK_BASENAME);
    }
    if (cwd >= 0) {
        if (fchdir(cwd) != 0) failures++;
        close(cwd);
    }
    return failures;
}

/* ── 3. the 1024-byte path limit ─────────────────────────────────── */

static int ae_long_lastgood(const char *mut, const char *cur)
{
    int failures = 0;
    char deep[4096];
    size_t blen = strlen(BINARY_AB_LASTGOOD_BASENAME);
    AE_CHECK("build a slots dir making last-good exactly 1024 bytes",
             ae_nested_dir(mut, 1024 - 1 - blen, deep, sizeof(deep)));
    AE_CHECK("seed candidate", ae_write_str(cur, "LONG-PATH", 0755));
    bool refused = !binary_ab_promote(deep, cur);
    int entries = 0, staging = 0;
    ae_scan(deep, &entries, &staging);
    AE_CHECK("a 1024-byte last-good path is refused, nothing created "
             "under a truncated name", refused && entries == 0);
    ae_rm_nested(mut, deep);

    AE_CHECK("build a slots dir making last-good 1023 bytes",
             ae_nested_dir(mut, 1024 - 2 - blen, deep, sizeof(deep)));
    bool ok = binary_ab_promote(deep, cur);
    char dst[4096];
    snprintf(dst, sizeof(dst), "%s/%s", deep, BINARY_AB_LASTGOOD_BASENAME);
    AE_CHECK("a 1023-byte last-good path is accepted and written whole",
             ok && ae_text_is(dst, "LONG-PATH"));
    (void)unlink(dst);
    ae_rm_nested(mut, deep);
    return failures;
}

static int ae_long_streak(const char *mut)
{
    int failures = 0;
    char deep[4096];
    size_t blen = strlen(BINARY_AB_STREAK_BASENAME);
    AE_CHECK("build a slots dir making the streak path exactly 1024 bytes",
             ae_nested_dir(mut, 1024 - 1 - blen, deep, sizeof(deep)));
    ae_env(BINARY_AB_ENV_SLOTS_DIR, deep);
    binary_ab_note_self_respawn_exit_env();
    int entries = 0, staging = 0;
    ae_scan(deep, &entries, &staging);
    AE_CHECK("a 1024-byte streak path is refused: no file under any name",
             entries == 0);
    ae_rm_nested(mut, deep);

    AE_CHECK("build a slots dir making the streak path 1023 bytes",
             ae_nested_dir(mut, 1024 - 2 - blen, deep, sizeof(deep)));
    ae_env(BINARY_AB_ENV_SLOTS_DIR, deep);
    char streak[4096];
    snprintf(streak, sizeof(streak), "%s/%s", deep, BINARY_AB_STREAK_BASENAME);
    AE_CHECK("seed the 1023-byte streak", ae_write_str(streak, "6\n", 0600));
    binary_ab_note_self_respawn_exit_env();
    AE_CHECK("a 1023-byte streak path is accepted and incremented",
             ae_text_is(streak, "7\n"));
    (void)unlink(streak);
    char lock[4096];
    snprintf(lock, sizeof(lock), "%s/.binary-slots.lock", deep);
    (void)unlink(lock);
    ae_rm_nested(mut, deep);
    ae_env(BINARY_AB_ENV_SLOTS_DIR, NULL);
    return failures;
}

/* ── 4. on_ready ─────────────────────────────────────────────────── */

static int ae_on_ready_cases(const char *mut, const char *cur,
                             const char *lastgood, const char *streak)
{
    int failures = 0;
    AE_CHECK("seed good last-good and streak",
             ae_write_str(lastgood, "GOOD", 0755) &&
             ae_write_str(streak, "4\n", 0600) &&
             ae_write_str(cur, "CANDIDATE", 0755));
    AE_CHECK("fallback ready with no current path still succeeds and "
             "resets the streak",
             binary_ab_on_ready(mut, NULL, true) &&
             ae_text_is(streak, "0\n") && ae_text_is(lastgood, "GOOD"));
    AE_CHECK("an empty current path is refused on a normal ready",
             !binary_ab_on_ready(mut, "", false));
    AE_CHECK("fallback ready against a missing slots dir reports the "
             "failed reset", !binary_ab_on_ready("/nonexistent-ab-slots-dir",
                                                 cur, true));

    AE_CHECK("make the streak path a directory so its reset must fail",
             unlink(streak) == 0 && mkdir(streak, 0700) == 0);
    AE_CHECK("normal ready: promotion lands but a failed streak reset is "
             "reported false",
             !binary_ab_on_ready(mut, cur, false) &&
             ae_text_is(lastgood, "CANDIDATE"));
    AE_CHECK("fallback ready: a failed streak reset is reported false",
             !binary_ab_on_ready(mut, cur, true));
    (void)rmdir(streak);
    return failures;
}

static void ae_do_ready_nocur(void)
{
    (void)binary_ab_on_ready(g_ae_arg, NULL, false);
}

static void ae_do_ready_fb(void)
{
    (void)binary_ab_on_ready(g_ae_arg, NULL, true);
}

static void ae_do_ready_bad_promote(void)
{
    (void)binary_ab_on_ready(g_ae_arg, "/nonexistent-ab-current", false);
}

static int ae_on_ready_logs(const char *mut)
{
    int failures = 0;
    snprintf(g_ae_arg, sizeof(g_ae_arg), "%s", mut);
    AE_CHECK("normal ready without a current path logs why",
             ae_capture(ae_do_ready_nocur) &&
             ae_logged("managed normal ready requires current_path"));
    AE_CHECK("ready under FALLBACK logs that last-good was left intact",
             ae_capture(ae_do_ready_fb) &&
             ae_logged("reached ready under FALLBACK slot") &&
             ae_logged("last-good left intact"));
    AE_CHECK("a failed promotion logs that the streak is preserved",
             ae_capture(ae_do_ready_bad_promote) &&
             ae_logged("ready promotion failed; streak preserved"));
    return failures;
}

/* ── 5. the blocker and its env wrapper ──────────────────────────── */

static int ae_blocker_cases(void)
{
    int failures = 0;
    struct blocker_snapshot snap;
    memset(&snap, 0, sizeof(snap));
    blocker_clear(BINARY_FALLBACK_BLOCKER_ID);
    binary_ab_raise_fallback_blocker(true);
    bool found = blocker_find_by_id_prefix(BINARY_FALLBACK_BLOCKER_ID, &snap);
    AE_CHECK("the blocker carries id, owner and class",
             found && strcmp(snap.id, BINARY_FALLBACK_BLOCKER_ID) == 0 &&
             strcmp(snap.owner_subsystem, BINARY_FALLBACK_BLOCKER_OWNER) == 0 &&
             snap.class == BLOCKER_PERMANENT);
    AE_CHECK("the reason names the threshold and the operator action",
             found && strstr(snap.reason, "last-known-good binary") &&
             strstr(snap.reason, "failed to reach activation-ready 3 times "
                                 "in a row") &&
             strstr(snap.reason, "deploy a working binary and clear the "
                                 "boot-failure streak"));
    blocker_clear(BINARY_FALLBACK_BLOCKER_ID);
    return failures;
}

static void ae_do_raise_env(void) { binary_ab_raise_fallback_blocker_env(); }

static int ae_blocker_env(const char *cap_unused)
{
    int failures = 0;
    (void)cap_unused;
    const char *off[] = { NULL, "", "0", "11", "10", "true" };
    for (size_t i = 0; i < sizeof(off) / sizeof(off[0]); i++) {
        blocker_clear(BINARY_FALLBACK_BLOCKER_ID);
        ae_env(BINARY_AB_ENV_FALLBACK, off[i]);
        binary_ab_raise_fallback_blocker_env();
        char label[64];
        snprintf(label, sizeof(label), "env fallback flag %s%s%s raises nothing",
                 off[i] ? "'" : "", off[i] ? off[i] : "unset",
                 off[i] ? "'" : "");
        AE_CHECK(label, !blocker_exists(BINARY_FALLBACK_BLOCKER_ID));
    }
    ae_env(BINARY_AB_ENV_FALLBACK, "1");
    AE_CHECK("env fallback flag '1' raises the blocker and logs it",
             ae_capture(ae_do_raise_env) &&
             blocker_exists(BINARY_FALLBACK_BLOCKER_ID) &&
             ae_logged("binary.fallback_active raised"));
    blocker_clear(BINARY_FALLBACK_BLOCKER_ID);
    ae_env(BINARY_AB_ENV_FALLBACK, NULL);
    return failures;
}

/* ── 6. promote-on-ready and self-respawn env wrappers ───────────── */

static void ae_do_promote_env(void) { binary_ab_promote_on_ready_env(); }

static int ae_env_noop(const char *mut, const char *lastgood,
                       const char *streak)
{
    int failures = 0;
    AE_CHECK("seed sentinel last-good and streak",
             ae_write_str(lastgood, "SENTINEL", 0755) &&
             ae_write_str(streak, "5\n", 0600));
    ae_env(BINARY_AB_ENV_FALLBACK, NULL);
    ae_env(BINARY_AB_ENV_SLOTS_DIR, NULL);
    binary_ab_promote_on_ready_env();
    binary_ab_note_self_respawn_exit_env();
    AE_CHECK("unset slots dir: both wrappers are no-ops",
             ae_text_is(lastgood, "SENTINEL") && ae_text_is(streak, "5\n"));
    ae_env(BINARY_AB_ENV_SLOTS_DIR, "");
    binary_ab_promote_on_ready_env();
    binary_ab_note_self_respawn_exit_env();
    AE_CHECK("empty slots dir: both wrappers are no-ops",
             ae_text_is(lastgood, "SENTINEL") && ae_text_is(streak, "5\n"));

    ae_env(BINARY_AB_ENV_SLOTS_DIR, mut);
    binary_ab_note_self_respawn_exit_env();
    AE_CHECK("self-respawn exit increments the managed streak",
             ae_text_is(streak, "6\n"));
    (void)unlink(streak);
    ae_env(BINARY_AB_ENV_SLOTS_DIR, NULL);
    return failures;
}

static int ae_env_fallback_ready(const char *mut, const char *lastgood,
                                 const char *streak)
{
    int failures = 0;
    AE_CHECK("seed sentinel last-good and streak 8",
             ae_write_str(lastgood, "SENTINEL", 0755) &&
             ae_write_str(streak, "8\n", 0600));
    ae_env(BINARY_AB_ENV_SLOTS_DIR, mut);
    ae_env(BINARY_AB_ENV_FALLBACK, "1");
    AE_CHECK("fallback env ready logs and returns",
             ae_capture(ae_do_promote_env) &&
             ae_logged("reached ready under FALLBACK slot"));
    AE_CHECK("fallback env ready resets the streak and never touches the "
             "last-good slot",
             ae_text_is(streak, "0\n") && ae_text_is(lastgood, "SENTINEL"));
    return failures;
}

/* Where the platform exposes the running image, compare byte for byte;
 * elsewhere the size and mode checks stand alone. */
static bool ae_is_self_image(const char *slot)
{
#if defined(__linux__)
    struct stat a, b;
    return stat(slot, &a) == 0 && stat("/proc/self/exe", &b) == 0 &&
           a.st_size == b.st_size && ae_files_equal(slot, "/proc/self/exe");
#else
    (void)slot;
    return true;
#endif
}

static int ae_env_promote_running(const char *mut, const char *lastgood,
                                  const char *streak, const char *fb)
{
    int failures = 0;
    struct stat st;
    AE_CHECK("seed sentinel last-good and streak 8",
             ae_write_str(lastgood, "SENTINEL", 0755) &&
             ae_write_str(streak, "8\n", 0600));
    ae_env(BINARY_AB_ENV_SLOTS_DIR, mut);
    ae_env(BINARY_AB_ENV_FALLBACK, fb);
    AE_CHECK("a flag other than exactly '1' promotes the running image",
             ae_capture(ae_do_promote_env) &&
             ae_logged("promoted current binary to last-good slot") &&
             !ae_logged("ready streak reset after promotion failed"));
    AE_CHECK("the slot is an executable, byte-exact copy of the image",
             stat(lastgood, &st) == 0 && st.st_size > 1024 &&
             (st.st_mode & S_IXUSR) && ae_is_self_image(lastgood));
    AE_CHECK("and the streak is reset after the promotion",
             ae_text_is(streak, "0\n"));
    return failures;
}

static int ae_env_promote_failures(const char *mut, const char *lastgood,
                                   const char *streak)
{
    int failures = 0;
    AE_CHECK("make the streak path a directory so its reset must fail",
             unlink(streak) == 0 && mkdir(streak, 0700) == 0);
    ae_env(BINARY_AB_ENV_SLOTS_DIR, mut);
    ae_env(BINARY_AB_ENV_FALLBACK, "11");
    AE_CHECK("a failed streak reset after a landed promotion is logged",
             ae_capture(ae_do_promote_env) &&
             ae_logged("ready streak reset after promotion failed"));
    (void)rmdir(streak);

    AE_CHECK("seed sentinel last-good", ae_write_str(lastgood, "SENTINEL",
                                                      0755));
    ae_env(BINARY_AB_ENV_SLOTS_DIR, "/nonexistent-ab-slots-dir");
    ae_env(BINARY_AB_ENV_FALLBACK, NULL);
    AE_CHECK("a failed running-image promotion is logged and nothing lands",
             ae_capture(ae_do_promote_env) &&
             ae_logged("ready promotion from running image failed") &&
             ae_text_is(lastgood, "SENTINEL"));
    return failures;
}

/* ── entry ────────────────────────────────────────────────────────── */

static int ae_run_cases(const char *mut, const char *cur,
                        const char *lastgood, const char *streak)
{
    int failures = 0;
    failures += ae_streak_increment(mut, streak);
    failures += ae_streak_reset_failures(mut);
    failures += ae_promote_boundaries(mut, cur, lastgood);
    failures += ae_promote_refusals(mut, cur, lastgood);
    failures += ae_promote_empty_source(mut, cur, lastgood);
    failures += ae_promote_after_injected_failure(mut, cur, lastgood);
    failures += ae_promote_short_relative(mut);
    failures += ae_long_lastgood(mut, cur);
    failures += ae_long_streak(mut);
    failures += ae_on_ready_cases(mut, cur, lastgood, streak);
    failures += ae_on_ready_logs(mut);
    failures += ae_blocker_cases();
    failures += ae_blocker_env(mut);
    failures += ae_env_noop(mut, lastgood, streak);
    failures += ae_env_fallback_ready(mut, lastgood, streak);
    failures += ae_env_promote_running(mut, lastgood, streak, "11");
    failures += ae_env_promote_failures(mut, lastgood, streak);
    return failures;
}

/* Named for its subject, not its file: a filename-matching name would be a
 * test-registration entry point. Dispatched from the posix arm of
 * test_binary_ab_fallback.c with that group's scratch directory. */
int ab_edges_contract(const char *dir);

int ab_edges_contract(const char *dir)
{
    int failures = 0;
    char mut[1100], cur[1200], lastgood[1200], streak[1200];
    snprintf(mut, sizeof(mut), "%s/edges", dir);
    if (mkdir(mut, 0700) != 0) {
        printf("ab edges: cannot create the fixture directory... FAIL\n");
        return 1;
    }
    g_ae_cap_dir = mut;
    snprintf(cur, sizeof(cur), "%s/current-bin", mut);
    snprintf(lastgood, sizeof(lastgood), "%s/%s", mut,
             BINARY_AB_LASTGOOD_BASENAME);
    snprintf(streak, sizeof(streak), "%s/%s", mut,
             BINARY_AB_STREAK_BASENAME);

    struct ae_env_save saved;
    ae_env_save(&saved);
    blocker_module_init();
    failures += ae_run_cases(mut, cur, lastgood, streak);
    ae_env_restore(&saved);

    char lock[1200];
    snprintf(lock, sizeof(lock), "%s/.binary-slots.lock", mut);
    (void)unlink(cur);
    (void)unlink(lastgood);
    (void)unlink(streak);
    (void)unlink(lock);
    (void)rmdir(mut);
    return failures;
}

#else  /* _WIN32: the whole A/B slot surface is refused by name; the main
        * file asserts that refusal. */

int ab_edges_contract(const char *dir);

int ab_edges_contract(const char *dir)
{
    (void)dir;
    return 0;
}

#endif
