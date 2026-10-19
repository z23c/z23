/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prove the plugin supervisor runs the current signed generation as a
 * confined child that holds only its granted descriptors, restarts it with
 * backoff after a kill or a hung ping, reloads one plugin without touching
 * another, and restores last-good once after a crash loop. The children are
 * patched copies of the static fixture plugin tests/harness/fixtures/
 * plugin_run_child.c; every plugin is signed with real Ed25519 and installed
 * through the plugin store. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "crypto/ed25519.h"
#include "json/json.h"
#include "platform/os_sandbox.h"
#include "platform/positioned_file.h"
#include "platform/resident_launch.h"
#include "util/path_util.h"
#include "plugin/plugin_run.h"
#include "plugin/plugin_store.h"
#include "sha3/sha3.h"

#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PRT_FIXTURE "build/fixtures/plugin_run_child"
#define PRT_HEX (PLUGIN_HEX_SHA3_512 + 1)
#define PRT_MARKER "PRC-VARIANT:"
#define PRT_FIELD 16

#if !defined(__linux__)
int test_plugin_run(void)
{
    int failures = 0;
    printf("\n=== Plugin run tests ===\n");
    TEST_CASE("running a plugin refuses by name off Linux") {
        struct plugin_run *run = NULL;
        struct plugin_run_options o = {.root = "/nonexistent", .name = "hello"};
        ASSERT_EQ(plugin_run_open(&o, &run, NULL), PLUGIN_RUN_ERR_PLATFORM);
    } TEST_END
    return failures;
}
#else

struct prt_env {
    char base[PATH_MAX], home[PATH_MAX], root[PATH_MAX], src[PATH_MAX];
    uint8_t pk[32], sk[32];
};

static void prt_hex(const uint8_t *in, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[in[i] >> 4];
        out[2 * i + 1] = d[in[i] & 15];
    }
    out[2 * n] = '\0';
}

static bool prt_write(const char *path, const void *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    bool ok = f && fwrite(data, 1, len, f) == len;
    if (f)
        ok = fclose(f) == 0 && ok;
    return ok;
}

static bool prt_slurp(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t n = fread(out, 1, cap - 1, f);
    fclose(f);
    out[n] = '\0';
    return true;
}

static bool prt_env_open(struct prt_env *e)
{
    char dot[PATH_MAX], keys[PATH_MAX], hex[65], line[80];
    uint8_t seed[32];
    memset(e, 0, sizeof(*e));
    memset(seed, 0x21, sizeof(seed));
    zcl_ed25519_keypair(e->pk, e->sk, seed);
    if (!test_mkdtemp(e->base, sizeof(e->base), "plugin_run"))
        return false;
    bool ok = zcl_path_join(e->home, sizeof(e->home), e->base, "home") &&
              mkdir(e->home, 0700) == 0 && zcl_path_join(dot, sizeof(dot), e->home, ".z23") &&
              mkdir(dot, 0700) == 0 && zcl_path_join(e->root, sizeof(e->root), dot, "plugins") &&
              mkdir(e->root, 0700) == 0 && zcl_path_join(e->src, sizeof(e->src), e->base, "src") &&
              mkdir(e->src, 0700) == 0 && zcl_path_join(keys, sizeof(keys), e->root, "publisher_keys");
    prt_hex(e->pk, 32, hex);
    snprintf(line, sizeof(line), "%s\n", hex);
    return ok && prt_write(keys, line, strlen(line)) && chmod(keys, 0600) == 0;
}

static void prt_env_close(struct prt_env *e)
{
    if (e->base[0])
        (void)test_rm_rf_recursive(e->base);
}

static unsigned char *prt_find(unsigned char *img, size_t size, const char *marker)
{
    size_t m = strlen(marker);
    for (size_t i = 0; i + m <= size; i++)
        if (memcmp(img + i, marker, m) == 0)
            return img + i;
    return NULL;
}

/* The fixture image with its behaviour field set to mode and its last two
 * characters to tag, so each (mode, tag) pair is a distinct generation. */
static unsigned char *prt_image(const char *mode, const char *tag, size_t *len)
{
    FILE *f = fopen(PRT_FIXTURE, "rb");
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);
    unsigned char *img = malloc((size_t)size);
    if (!img || fread(img, 1, (size_t)size, f) != (size_t)size) {
        fclose(f);
        free(img);
        return NULL;
    }
    fclose(f);
    unsigned char *at = prt_find(img, (size_t)size, PRT_MARKER);
    if (!at) {
        free(img);
        return NULL;
    }
    at += strlen(PRT_MARKER);
    memset(at, ' ', PRT_FIELD);
    memcpy(at, mode, strlen(mode));
    memcpy(at + PRT_FIELD - 2, tag, 2);
    *len = (size_t)size;
    return img;
}

static void prt_digest(const char *manifest, unsigned char digest[64])
{
    static const unsigned char domain[] = "z23.plugin.manifest.v1";
    struct sha3_512_ctx ctx;
    sha3_512_init(&ctx);
    sha3_512_write(&ctx, domain, sizeof(domain));
    sha3_512_write(&ctx, (const unsigned char *)manifest, strlen(manifest));
    sha3_512_finalize(&ctx, digest);
}

static void prt_sign(const struct prt_env *e, const char *manifest, char sig_hex[129])
{
    unsigned char digest[64];
    uint8_t sig[64];
    prt_digest(manifest, digest);
    zcl_ed25519_sign(sig, digest, sizeof(digest), e->sk, e->pk);
    prt_hex(sig, 64, sig_hex);
}

/* Sign and install an image as one generation; gen receives its id. Does not
 * switch. */
static bool prt_publish_bytes(struct prt_env *e, const char *name, const unsigned char *img,
                              size_t len, const char *caps, char gen[PRT_HEX])
{
    unsigned char digest[64];
    char exe_hex[PRT_HEX], sig_hex[129], pub[65], manifest[1024], doc[512], path[PATH_MAX], leaf[96];
    zcl_sha3_512(img, len, digest);
    prt_hex(digest, 64, exe_hex);
    snprintf(manifest, sizeof(manifest),
             "{\"schema\":\"z23.plugin.v1\",\"name\":\"%s\",\"version\":\"1.0.0\","
             "\"interface_version\":1,\"sha3_512\":\"%s\",\"capabilities\":[%s]}",
             name, exe_hex, caps);
    /* the generation id is the signed manifest digest, covering the capabilities */
    prt_digest(manifest, digest);
    prt_hex(digest, 64, gen);
    prt_sign(e, manifest, sig_hex);
    prt_hex(e->pk, 32, pub);
    snprintf(doc, sizeof(doc),
             "{\"sig_alg\":\"ed25519\",\"public_key\":\"%s\",\"signature\":\"%s\"}", pub, sig_hex);
    snprintf(leaf, sizeof(leaf), "%s.plugin.json", name);
    char manifest_path[PATH_MAX];
    bool ok = zcl_path_join(manifest_path, sizeof(manifest_path), e->src, leaf) &&
              prt_write(manifest_path, manifest, strlen(manifest));
    snprintf(leaf, sizeof(leaf), "%s.plugin.sig", name);
    ok = ok && zcl_path_join(path, sizeof(path), e->src, leaf) && prt_write(path, doc, strlen(doc)) &&
         zcl_path_join(path, sizeof(path), e->src, name) && prt_write(path, img, len);
    struct plugin_manifest m;
    int present = 0;
    return ok && plugin_store_install(e->root, manifest_path, &m, &present) == PLUGIN_OK;
}

static bool prt_publish(struct prt_env *e, const char *name, const char *mode,
                        const char *tag, const char *caps, char gen[PRT_HEX])
{
    size_t len = 0;
    unsigned char *img = prt_image(mode, tag, &len);
    bool ok = img && prt_publish_bytes(e, name, img, len, caps, gen);
    free(img);
    return ok;
}

static bool prt_install(struct prt_env *e, const char *name, const char *mode,
                        const char *tag, const char *caps, char gen[PRT_HEX])
{
    return prt_publish(e, name, mode, tag, caps, gen) &&
           plugin_store_switch(e->root, name, gen) == PLUGIN_OK;
}

static void prt_link(const struct prt_env *e, const char *name, const char *link,
                     char out[PRT_HEX])
{
    char dir[PATH_MAX], path[PATH_MAX], target[PATH_MAX];
    out[0] = '\0';
    if (!zcl_path_join(dir, sizeof(dir), e->root, name) || !zcl_path_join(path, sizeof(path), dir, link))
        return;
    ssize_t n = readlink(path, target, sizeof(target) - 1);
    if (n > 12 && (size_t)n - 12 < PRT_HEX) {
        target[n] = '\0';
        memcpy(out, target + 12, (size_t)n - 11);
    }
}

static struct plugin_run_options prt_options(const struct prt_env *e, const char *name)
{
    return (struct plugin_run_options){
        .root = e->root, .name = name,
        .ping_interval_ms = 40, .ping_deadline_ms = 500, .ping_miss_limit = 2,
        .backoff_initial_ms = 20, .backoff_max_ms = 2000, .stable_ms = 60000,
    };
}

static struct plugin_run *prt_open(const struct prt_env *e, const char *name)
{
    struct plugin_run_options o = prt_options(e, name);
    struct plugin_run *run = NULL;
    return plugin_run_open(&o, &run, NULL) == PLUGIN_RUN_OK ? run : NULL;
}

/* For children that die by a signal: a core-dumping process can linger for
 * seconds on a busy host, and a missed-ping kill must not replace its status. */
static struct plugin_run *prt_open_patient(const struct prt_env *e, const char *name)
{
    struct plugin_run_options o = prt_options(e, name);
    struct plugin_run *run = NULL;
    o.ping_deadline_ms = 20000;
    return plugin_run_open(&o, &run, NULL) == PLUGIN_RUN_OK ? run : NULL;
}

typedef bool (*prt_pred)(const struct plugin_run_info *info, const void *ctx);

static uint64_t prt_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* Poll every run until pred holds for runs[watch], or timeout_ms passes. */
static bool prt_wait(struct plugin_run *const *runs, size_t n, size_t watch,
                     prt_pred pred, const void *ctx, unsigned timeout_ms)
{
    uint64_t end = prt_now_ms() + timeout_ms;
    struct plugin_run_info info;
    while (prt_now_ms() < end) {
        for (size_t i = 0; i < n; i++)
            (void)plugin_run_poll(runs[i]);
        plugin_run_info_get(runs[watch], &info);
        if (pred(&info, ctx))
            return true;
        struct timespec nap = {0, 5 * 1000 * 1000};
        nanosleep(&nap, NULL);
    }
    return false;
}

static bool prt_healthy(const struct plugin_run_info *i, const void *ctx)
{
    (void)ctx;
    return i->state == PLUGIN_RUN_STATE_RUNNING && i->pings_ok >= 1;
}

static bool prt_new_pid(const struct plugin_run_info *i, const void *ctx)
{
    uint64_t old = *(const uint64_t *)ctx;
    return i->state == PLUGIN_RUN_STATE_RUNNING && i->pid != 0 && i->pid != old;
}

static bool prt_exit_code(const struct plugin_run_info *i, const void *ctx)
{
    return i->last_exit_code == *(const int *)ctx;
}

static bool prt_file_exists(const struct plugin_run_info *i, const void *ctx)
{
    (void)i;
    return access((const char *)ctx, F_OK) == 0;
}

static bool prt_waiting(const struct plugin_run_info *i, const void *ctx)
{
    (void)ctx;
    return i->state == PLUGIN_RUN_STATE_BACKOFF;
}

static bool prt_hung_restarted(const struct plugin_run_info *i, const void *ctx)
{
    (void)ctx;
    return i->restarts >= 1;
}

static bool prt_signaled(const struct plugin_run_info *i, const void *ctx)
{
    return i->last_exit_signal == *(const int *)ctx;
}

static bool prt_fell_back(const struct plugin_run_info *i, const void *ctx)
{
    (void)ctx;
    return i->fell_back && i->state == PLUGIN_RUN_STATE_RUNNING && i->pings_ok >= 1;
}

static bool prt_crashed_often(const struct plugin_run_info *i, const void *ctx)
{
    return i->restarts >= *(const unsigned *)ctx;
}

static bool prt_report(const struct prt_env *e, const char *name, char *out, size_t cap)
{
    char dir[PATH_MAX], data[PATH_MAX], path[PATH_MAX];
    return zcl_path_join(dir, sizeof(dir), e->root, name) && zcl_path_join(data, sizeof(data), dir, "data") &&
           zcl_path_join(path, sizeof(path), data, "report.txt") && prt_slurp(path, out, cap);
}

static const char *PRT_FS = "\"fs.write\",\"clock\"";

static int prt_case_descriptors(void)
{
    int failures = 0;
    struct prt_env e;
    struct plugin_run *run = NULL;
    bool ready = prt_env_open(&e);
    TEST_CASE("only the granted descriptors are open and stdio is /dev/null") {
        char gen[PRT_HEX], report[1024];
        struct plugin_run_info info;
        ASSERT(ready);
        ASSERT(access(PRT_FIXTURE, X_OK) == 0);
        ASSERT(prt_install(&e, "alpha", "normal", "a1", PRT_FS, gen));
        run = prt_open(&e, "alpha");
        ASSERT(run != NULL);
        ASSERT(prt_wait(&run, 1, 0, prt_healthy, NULL, 5000));
        plugin_run_info_get(run, &info);
        ASSERT_STR_EQ(info.generation, gen);
        ASSERT(info.pid != 0);
        ASSERT(prt_report(&e, "alpha", report, sizeof(report)));
        ASSERT(strstr(report, "fds=0,1,2,3,4,5\n") != NULL);
        ASSERT(strstr(report, "env=Z23_PLUGIN_FDS=control=3,data.dir=4,log=5\n") != NULL ||
               strstr(report, "env=control=3,data.dir=4,log=5\n") != NULL);
        ASSERT(strstr(report, "stdio_null=1\n") != NULL);
        ASSERT(strstr(report, "nnp=1\n") != NULL);
        ASSERT(prt_wait(&run, 1, 0, prt_healthy, NULL, 1000));
        plugin_run_info_get(run, &info);
        ASSERT(info.log_bytes >= 16);
        ASSERT_EQ(info.restarts, 0u);
    } TEST_END
    plugin_run_close(run);
    prt_env_close(&e);
    return failures;
}

static int prt_case_confinement(void)
{
    int failures = 0;
    struct prt_env e;
    struct plugin_run *run = NULL, *killed = NULL;
    bool ready = prt_env_open(&e);
    TEST_CASE("a write outside data.dir fails and socket() kills the plugin") {
        char gen[PRT_HEX], report[1024], outside[PATH_MAX];
        int sigsys = SIGSYS;
        struct plugin_run_info info;
        ASSERT(ready);
        ASSERT(prt_install(&e, "writer", "write-outside", "w1", PRT_FS, gen));
        run = prt_open(&e, "writer");
        ASSERT(run != NULL);
        ASSERT(prt_wait(&run, 1, 0, prt_healthy, NULL, 5000));
        ASSERT(prt_report(&e, "writer", report, sizeof(report)));
        ASSERT(strstr(report, "write_outside=13\n") != NULL);
        ASSERT(strstr(report, "write_shm=13\n") != NULL);
        ASSERT(strstr(report, "read_passwd=13\n") != NULL);
        ASSERT(snprintf(outside, sizeof(outside), "%s/writer/outside.txt", e.root) > 0);
        ASSERT(access(outside, F_OK) != 0);
        ASSERT(access("/dev/shm/z23-plugin-run-outside", F_OK) != 0);
        ASSERT(prt_install(&e, "sock", "try-socket", "s1", PRT_FS, gen));
        killed = prt_open_patient(&e, "sock");
        ASSERT(killed != NULL);
        ASSERT(prt_wait(&killed, 1, 0, prt_signaled, &sigsys, 15000));
        plugin_run_info_get(killed, &info);
        ASSERT_EQ(info.last_exit_signal, SIGSYS);
        ASSERT(info.crashes >= 1);
    } TEST_END
    plugin_run_close(run);
    plugin_run_close(killed);
    prt_env_close(&e);
    return failures;
}

static int prt_case_kill_backoff(void)
{
    int failures = 0;
    struct prt_env e;
    struct plugin_run *run = NULL;
    bool ready = prt_env_open(&e);
    TEST_CASE("a killed plugin waits in backoff, then restarts with a doubled delay") {
        char gen[PRT_HEX];
        struct plugin_run_info info;
        struct plugin_run_options o;
        ASSERT(ready);
        ASSERT(prt_install(&e, "alpha", "normal", "a1", PRT_FS, gen));
        o = prt_options(&e, "alpha");
        o.backoff_initial_ms = 150;
        ASSERT_EQ(plugin_run_open(&o, &run, NULL), PLUGIN_RUN_OK);
        for (unsigned round = 1; round <= 2; round++) {
            uint64_t pid;
            ASSERT(prt_wait(&run, 1, 0, prt_healthy, NULL, 5000));
            plugin_run_info_get(run, &info);
            pid = info.pid;
            ASSERT_EQ(kill((pid_t)pid, SIGKILL), 0);
            ASSERT(prt_wait(&run, 1, 0, prt_waiting, NULL, 5000));
            plugin_run_info_get(run, &info);
            ASSERT_EQ(info.pid, 0u);
            ASSERT_EQ(info.restarts, round - 1);
            ASSERT_EQ(info.last_exit_signal, SIGKILL);
            ASSERT_EQ(info.backoff_ms, 150u << round);
            ASSERT(prt_wait(&run, 1, 0, prt_new_pid, &pid, 5000));
            plugin_run_info_get(run, &info);
            ASSERT_EQ(info.restarts, round);
        }
    } TEST_END
    plugin_run_close(run);
    prt_env_close(&e);
    return failures;
}

static bool prt_failed(const struct plugin_run_info *i, const void *ctx)
{
    (void)ctx;
    return i->state == PLUGIN_RUN_STATE_FAILED;
}

/* Write publisher_keys as the signer's key plus an optional second key line, or
 * with the signer left out entirely. */
static bool prt_set_keys(const struct prt_env *e, bool signer, const char *extra)
{
    char path[PATH_MAX], hex[65], body[200];
    prt_hex(e->pk, 32, hex);
    snprintf(body, sizeof(body), "%s%s%s%s", signer ? hex : "", signer ? "\n" : "",
             extra ? extra : "", extra ? "\n" : "");
    return zcl_path_join(path, sizeof(path), e->root, "publisher_keys") &&
           prt_write(path, body, strlen(body));
}

#define PRT_OTHER_KEY "1111111111111111111111111111111111111111111111111111111111111111"

static bool prt_restart_once(struct plugin_run **run)
{
    struct plugin_run_info info;
    plugin_run_info_get(*run, &info);
    uint64_t pid = info.pid;
    return kill((pid_t)pid, SIGKILL) == 0 && prt_wait(run, 1, 0, prt_new_pid, &pid, 5000);
}

static int prt_case_verify_cache(void)
{
    int failures = 0;
    struct prt_env e;
    struct plugin_run *run = NULL;
    bool ready = prt_env_open(&e);
    TEST_CASE("restarts reuse a verified generation until publisher_keys changes") {
        char gen[PRT_HEX];
        struct plugin_run_info info;
        unsigned base;
        ASSERT(ready);
        ASSERT(prt_install(&e, "vc", "normal", "v1", PRT_FS, gen));
        run = prt_open(&e, "vc");
        ASSERT(run != NULL);
        base = plugin_run_test_verify_count();
        ASSERT(prt_wait(&run, 1, 0, prt_healthy, NULL, 5000));
        ASSERT(prt_restart_once(&run));
        ASSERT(prt_wait(&run, 1, 0, prt_healthy, NULL, 5000));
        ASSERT_EQ(plugin_run_test_verify_count(), base);
        ASSERT_EQ(plugin_run_reload(run), PLUGIN_RUN_OK);
        ASSERT_EQ(plugin_run_test_verify_count(), base);
        /* an extra listed key changes the digest: the signature is checked again */
        ASSERT(prt_wait(&run, 1, 0, prt_healthy, NULL, 5000));
        ASSERT(prt_set_keys(&e, true, PRT_OTHER_KEY));
        ASSERT(prt_restart_once(&run));
        ASSERT_EQ(plugin_run_test_verify_count(), base + 1);
        ASSERT(prt_wait(&run, 1, 0, prt_healthy, NULL, 5000));
        ASSERT(prt_restart_once(&run));
        ASSERT_EQ(plugin_run_test_verify_count(), base + 1);
        /* revoking the signer must refuse the next restart */
        ASSERT(prt_wait(&run, 1, 0, prt_healthy, NULL, 5000));
        ASSERT(prt_set_keys(&e, false, PRT_OTHER_KEY));
        plugin_run_info_get(run, &info);
        ASSERT_EQ(kill((pid_t)info.pid, SIGKILL), 0);
        ASSERT(prt_wait(&run, 1, 0, prt_failed, NULL, 5000));
        ASSERT_EQ(plugin_run_test_verify_count(), base + 2);
        plugin_run_info_get(run, &info);
        ASSERT_EQ(info.pid, 0u);
        ASSERT(strstr(info.detail, "plugin store refused") != NULL);
    } TEST_END
    plugin_run_close(run);
    prt_env_close(&e);
    return failures;
}

static int prt_case_cached_exe_hash(void)
{
    int failures = 0;
    struct prt_env e;
    struct plugin_run *run = NULL;
    bool ready = prt_env_open(&e);
    TEST_CASE("a cached generation still hashes the executable on every launch") {
        char gen[PRT_HEX], exe[PATH_MAX];
        struct plugin_run_info info;
        unsigned base;
        uint64_t pid;
        ASSERT(ready);
        ASSERT(prt_install(&e, "vx", "normal", "x1", PRT_FS, gen));
        run = prt_open(&e, "vx");
        ASSERT(run != NULL);
        base = plugin_run_test_verify_count();
        ASSERT(prt_wait(&run, 1, 0, prt_healthy, NULL, 5000));
        plugin_run_info_get(run, &info);
        pid = info.pid;
        ASSERT_EQ(kill((pid_t)pid, SIGKILL), 0);
        ASSERT(prt_wait(&run, 1, 0, prt_waiting, NULL, 5000));
        snprintf(exe, sizeof(exe), "%s/vx/generations/%s/vx", e.root, gen);
        ASSERT_EQ(chmod(exe, 0755), 0);
        ASSERT(prt_write(exe, "evil", 4));
        ASSERT(!prt_wait(&run, 1, 0, prt_new_pid, &pid, 600));
        plugin_run_info_get(run, &info);
        ASSERT_EQ(info.pid, 0u);
        ASSERT(info.crashes >= 2);
        ASSERT_EQ(plugin_run_test_verify_count(), base);
    } TEST_END
    plugin_run_close(run);
    prt_env_close(&e);
    return failures;
}

/* Race the verification: the key list is A (signer absent) when it is read,
 * B (signer present) while the verifier could open it, and A again before the
 * result is remembered. */
static void prt_aba_hook(int point, void *ctx)
{
    const struct prt_env *e = ctx;
    (void)prt_set_keys(e, point == PLUGIN_RUN_TEST_AFTER_KEYS, PRT_OTHER_KEY);
}

static int prt_case_keys_aba(void)
{
    int failures = 0;
    struct prt_env e;
    struct plugin_run *run = NULL, *again = NULL;
    bool ready = prt_env_open(&e);
    TEST_CASE("a key list swapped to B and back to A during verify authorizes nothing") {
        char gen[PRT_HEX];
        struct plugin_run_options o;
        enum plugin_status store = PLUGIN_OK;
        ASSERT(ready);
        ASSERT(prt_install(&e, "ab", "normal", "a1", PRT_FS, gen));
        ASSERT(prt_set_keys(&e, false, PRT_OTHER_KEY));
        o = prt_options(&e, "ab");
        plugin_run_test_set_hook(prt_aba_hook, &e);
        ASSERT_EQ(plugin_run_open(&o, &run, &store), PLUGIN_RUN_ERR_STORE);
        plugin_run_test_set_hook(NULL, NULL);
        ASSERT_EQ(store, PLUGIN_ERR_KEY_UNKNOWN);
        ASSERT(run == NULL);
        /* nothing may have been remembered under A either */
        store = PLUGIN_OK;
        ASSERT(prt_set_keys(&e, false, PRT_OTHER_KEY));
        ASSERT_EQ(plugin_run_open(&o, &again, &store), PLUGIN_RUN_ERR_STORE);
        ASSERT_EQ(store, PLUGIN_ERR_KEY_UNKNOWN);
    } TEST_END
    plugin_run_test_set_hook(NULL, NULL);
    plugin_run_close(run);
    plugin_run_close(again);
    prt_env_close(&e);
    return failures;
}

/* Make one level of the generation chain group-writable after a restart
 * verified and remembered the generation: the next restart must refuse. */
static int prt_case_cached_unsafe_dir(const char *title, const char *name, bool whole_gens)
{
    int failures = 0;
    struct prt_env e;
    struct plugin_run *run = NULL;
    bool ready = prt_env_open(&e);
    TEST_CASE(title) {
        char gen[PRT_HEX], dir[PATH_MAX];
        struct plugin_run_info info;
        ASSERT(ready);
        ASSERT(prt_install(&e, name, "normal", "u1", PRT_FS, gen));
        run = prt_open(&e, name);
        ASSERT(run != NULL);
        ASSERT(prt_wait(&run, 1, 0, prt_healthy, NULL, 5000));
        ASSERT(prt_restart_once(&run));
        ASSERT(prt_wait(&run, 1, 0, prt_healthy, NULL, 5000));
        snprintf(dir, sizeof(dir), "%s/%s/generations%s%s", e.root, name,
                 whole_gens ? "" : "/", whole_gens ? "" : gen);
        ASSERT_EQ(chmod(dir, 0777), 0);
        plugin_run_info_get(run, &info);
        ASSERT_EQ(kill((pid_t)info.pid, SIGKILL), 0);
        ASSERT(prt_wait(&run, 1, 0, prt_failed, NULL, 5000));
        plugin_run_info_get(run, &info);
        ASSERT_EQ(info.pid, 0u);
        ASSERT(strstr(info.detail, "plugin store refused") != NULL);
        ASSERT(strstr(info.detail, "PLUGIN_KEYS_INSECURE") != NULL);
    } TEST_END
    plugin_run_close(run);
    prt_env_close(&e);
    return failures;
}

static int prt_case_hung_ping(void)
{
    int failures = 0;
    struct prt_env e;
    struct plugin_run *run = NULL;
    bool ready = prt_env_open(&e);
    TEST_CASE("a plugin that stops answering pings is killed and restarted") {
        char gen[PRT_HEX];
        struct plugin_run_info info;
        struct plugin_run_options o;
        ASSERT(ready);
        ASSERT(prt_install(&e, "hang", "hang", "h1", PRT_FS, gen));
        o = prt_options(&e, "hang");
        o.ping_interval_ms = 20;
        o.ping_deadline_ms = 80;
        ASSERT_EQ(plugin_run_open(&o, &run, NULL), PLUGIN_RUN_OK);
        ASSERT(prt_wait(&run, 1, 0, prt_hung_restarted, NULL, 5000));
        plugin_run_info_get(run, &info);
        ASSERT_EQ(info.pings_ok, 0u);
        ASSERT_EQ(info.last_exit_signal, SIGKILL);
        ASSERT(info.crashes >= 1);
    } TEST_END
    plugin_run_close(run);
    prt_env_close(&e);
    return failures;
}

static int prt_case_reload(void)
{
    int failures = 0;
    struct prt_env e;
    struct plugin_run *runs[2] = {NULL, NULL};
    bool ready = prt_env_open(&e);
    TEST_CASE("reload runs the new generation and leaves another plugin alone") {
        char a1[PRT_HEX], a2[PRT_HEX], b1[PRT_HEX];
        struct plugin_run_info alpha, beta;
        uint64_t old_alpha, old_beta;
        ASSERT(ready);
        ASSERT(prt_install(&e, "alpha", "normal", "a1", PRT_FS, a1));
        ASSERT(prt_install(&e, "beta", "normal", "b1", PRT_FS, b1));
        runs[0] = prt_open(&e, "alpha");
        runs[1] = prt_open(&e, "beta");
        ASSERT(runs[0] && runs[1]);
        ASSERT(prt_wait(runs, 2, 0, prt_healthy, NULL, 5000));
        ASSERT(prt_wait(runs, 2, 1, prt_healthy, NULL, 5000));
        plugin_run_info_get(runs[0], &alpha);
        plugin_run_info_get(runs[1], &beta);
        old_alpha = alpha.pid;
        old_beta = beta.pid;
        ASSERT_STR_EQ(alpha.generation, a1);
        ASSERT(prt_publish(&e, "alpha", "normal", "a2", PRT_FS, a2));
        ASSERT(strcmp(a1, a2) != 0);
        ASSERT_EQ(plugin_store_switch(e.root, "alpha", a2), PLUGIN_OK);
        plugin_run_info_get(runs[0], &alpha);
        ASSERT_STR_EQ(alpha.generation, a1);
        ASSERT_EQ(plugin_run_reload(runs[0]), PLUGIN_RUN_OK);
        ASSERT(prt_wait(runs, 2, 0, prt_new_pid, &old_alpha, 5000));
        ASSERT(prt_wait(runs, 2, 0, prt_healthy, NULL, 5000));
        plugin_run_info_get(runs[0], &alpha);
        plugin_run_info_get(runs[1], &beta);
        ASSERT_STR_EQ(alpha.generation, a2);
        ASSERT(alpha.pid != old_alpha);
        ASSERT_EQ(beta.pid, old_beta);
        ASSERT_STR_EQ(beta.generation, b1);
        ASSERT_EQ(beta.restarts, 0u);
    } TEST_END
    plugin_run_close(runs[0]);
    plugin_run_close(runs[1]);
    prt_env_close(&e);
    return failures;
}

static int prt_case_reload_refused(void)
{
    int failures = 0;
    struct prt_env e;
    struct plugin_run *run = NULL;
    bool ready = prt_env_open(&e);
    TEST_CASE("a reload onto a tampered generation leaves the running child alone") {
        char g1[PRT_HEX], g2[PRT_HEX], g3[PRT_HEX], exe[PATH_MAX];
        struct plugin_run_info info;
        static volatile sig_atomic_t stop, reload;
        uint64_t old_pid;
        ASSERT(ready);
        ASSERT(prt_install(&e, "keep", "normal", "k1", PRT_FS, g1));
        run = prt_open(&e, "keep");
        ASSERT(run != NULL);
        ASSERT(prt_wait(&run, 1, 0, prt_healthy, NULL, 5000));
        plugin_run_info_get(run, &info);
        old_pid = info.pid;
        ASSERT(old_pid != 0);
        /* a new generation whose executable bytes no longer match its signed hash */
        ASSERT(prt_install(&e, "keep", "normal", "k2", PRT_FS, g2));
        snprintf(exe, sizeof(exe), "%s/keep/generations/%s/keep", e.root, g2);
        ASSERT_EQ(chmod(exe, 0755), 0);
        ASSERT(prt_write(exe, "evil", 4));
        ASSERT_EQ(plugin_run_reload(run), PLUGIN_RUN_ERR_STORE);
        plugin_run_info_get(run, &info);
        ASSERT_EQ(info.pid, old_pid);
        ASSERT_EQ(info.state, PLUGIN_RUN_STATE_RUNNING);
        ASSERT_STR_EQ(info.generation, g1);
        ASSERT(strstr(info.detail, "plugin store refused") != NULL);
        ASSERT_EQ(kill((pid_t)old_pid, 0), 0);
        /* the loop keeps supervising the old child through a refused reload */
        reload = 1;
        ASSERT_EQ(plugin_run_loop(run, &stop, &reload, 200), PLUGIN_RUN_OK);
        plugin_run_info_get(run, &info);
        ASSERT_EQ(info.pid, old_pid);
        ASSERT_EQ(info.state, PLUGIN_RUN_STATE_RUNNING);
        /* a valid generation afterwards still takes over: the refusal wedged nothing */
        ASSERT(prt_install(&e, "keep", "normal", "k3", PRT_FS, g3));
        ASSERT_EQ(plugin_run_reload(run), PLUGIN_RUN_OK);
        ASSERT(prt_wait(&run, 1, 0, prt_new_pid, &old_pid, 5000));
        ASSERT(prt_wait(&run, 1, 0, prt_healthy, NULL, 5000));
        plugin_run_info_get(run, &info);
        ASSERT_STR_EQ(info.generation, g3);
        ASSERT(info.pid != old_pid);
    } TEST_END
    plugin_run_close(run);
    prt_env_close(&e);
    return failures;
}

static int prt_case_crash_loop(void)
{
    int failures = 0;
    struct prt_env e;
    struct plugin_run *run = NULL;
    bool ready = prt_env_open(&e);
    TEST_CASE("three crashes after a switch restore last-good once") {
        char good[PRT_HEX], bad[PRT_HEX], current[PRT_HEX];
        struct plugin_run_info info;
        struct plugin_run_options o;
        ASSERT(ready);
        ASSERT(prt_install(&e, "loop", "normal", "g1", PRT_FS, good));
        ASSERT(prt_install(&e, "loop", "crash", "c1", PRT_FS, bad));
        prt_link(&e, "loop", "current", current);
        ASSERT_STR_EQ(current, bad);
        o = prt_options(&e, "loop");
        o.crash_limit = 3;
        ASSERT_EQ(plugin_run_open(&o, &run, NULL), PLUGIN_RUN_OK);
        ASSERT(prt_wait(&run, 1, 0, prt_fell_back, NULL, 10000));
        plugin_run_info_get(run, &info);
        ASSERT_STR_EQ(info.generation, good);
        prt_link(&e, "loop", "current", current);
        ASSERT_STR_EQ(current, good);
    } TEST_END
    plugin_run_close(run);
    prt_env_close(&e);
    return failures;
}

static int prt_case_crash_no_fallback(void)
{
    int failures = 0;
    struct prt_env e;
    struct plugin_run *alone = NULL;
    bool ready = prt_env_open(&e);
    TEST_CASE("a crash loop with no last-good keeps retrying and changes no link") {
        char only[PRT_HEX], current[PRT_HEX];
        struct plugin_run_info info;
        unsigned want = 5;
        ASSERT(ready);
        ASSERT(prt_install(&e, "solo", "crash", "c1", PRT_FS, only));
        alone = prt_open(&e, "solo");
        ASSERT(alone != NULL);
        ASSERT(prt_wait(&alone, 1, 0, prt_crashed_often, &want, 10000));
        plugin_run_info_get(alone, &info);
        ASSERT(!info.fell_back);
        ASSERT(info.state != PLUGIN_RUN_STATE_FAILED);
        prt_link(&e, "solo", "current", current);
        ASSERT_STR_EQ(current, only);
    } TEST_END
    plugin_run_close(alone);
    prt_env_close(&e);
    return failures;
}

static int prt_case_refusals(void)
{
    int failures = 0;
    struct prt_env e;
    bool ready = prt_env_open(&e);
    TEST_CASE("unsupported capabilities, missing and altered plugins are refused by name") {
        char gen[PRT_HEX], exe[PATH_MAX];
        struct plugin_run *run = NULL;
        struct plugin_run_options o;
        enum plugin_status store = PLUGIN_OK;
        ASSERT(ready);
        ASSERT(prt_install(&e, "net", "normal", "n1", "\"net.client\"", gen));
        o = prt_options(&e, "net");
        ASSERT_EQ(plugin_run_open(&o, &run, &store), PLUGIN_RUN_ERR_CAPABILITY);
        ASSERT(run == NULL);
        ASSERT(prt_install(&e, "spawner", "normal", "p1", "\"process.spawn\"", gen));
        o = prt_options(&e, "spawner");
        ASSERT_EQ(plugin_run_open(&o, &run, &store), PLUGIN_RUN_ERR_CAPABILITY);
        o = prt_options(&e, "nothing");
        ASSERT_EQ(plugin_run_open(&o, &run, &store), PLUGIN_RUN_ERR_STORE);
        ASSERT_EQ(store, PLUGIN_ERR_NOT_INSTALLED);
        ASSERT(prt_install(&e, "tamper", "normal", "t1", PRT_FS, gen));
        snprintf(exe, sizeof(exe), "%s/tamper/generations/%s/tamper", e.root, gen);
        ASSERT_EQ(chmod(exe, 0755), 0);
        ASSERT(prt_write(exe, "evil", 4));
        o = prt_options(&e, "tamper");
        ASSERT_EQ(plugin_run_open(&o, &run, &store), PLUGIN_RUN_ERR_STORE);
        ASSERT_EQ(store, PLUGIN_ERR_EXE_HASH);
        o.name = "../escape";
        ASSERT_EQ(plugin_run_open(&o, &run, &store), PLUGIN_RUN_ERR_ARGUMENT);
        ASSERT_STR_EQ(plugin_run_status_code(PLUGIN_RUN_ERR_CAPABILITY), "PLUGIN_RUN_CAPABILITY");
    } TEST_END
    prt_env_close(&e);
    return failures;
}

static bool prt_accept(const char *path, struct resident_launch_accepted *a);

static const char *const PRT_FORBIDDEN[] = {
    "ptrace", "mount", "unshare", "bpf", "uring", "keyctl", "kill", "pidfd", "chmod",
    "tkill", "tgkill", "vmread", "setxattr", "utimensat", "fchmodat2", "abort",
#ifdef SYS_fork
    "fork",
#endif
#ifdef SYS_vfork
    "vfork",
#endif
};

static int prt_case_forbidden_calls(void)
{
    int failures = 0;
    struct prt_env e;
    struct plugin_run *run = NULL;
    bool ready = prt_env_open(&e);
    TEST_CASE("each forbidden system call kills the plugin with SIGSYS") {
        ASSERT(ready);
        for (size_t i = 0; i < sizeof(PRT_FORBIDDEN) / sizeof(PRT_FORBIDDEN[0]); i++) {
            char name[32], gen[PRT_HEX], victim[PATH_MAX], dir[PATH_MAX];
            int sigsys = SIGSYS;
            snprintf(name, sizeof(name), "f-%s", PRT_FORBIDDEN[i]);
            ASSERT(prt_install(&e, name, PRT_FORBIDDEN[i], "f1", PRT_FS, gen));
            ASSERT(zcl_path_join(dir, sizeof(dir), e.root, name));
            ASSERT(zcl_path_join(victim, sizeof(victim), dir, "victim.txt"));
            ASSERT(prt_write(victim, "keep", 4));
            run = prt_open_patient(&e, name);
            ASSERT(run != NULL);
            if (!prt_wait(&run, 1, 0, prt_signaled, &sigsys, 15000))
                printf("[%s did not end in SIGSYS] ", PRT_FORBIDDEN[i]);
            struct plugin_run_info info;
            plugin_run_info_get(run, &info);
            ASSERT_EQ(info.last_exit_signal, SIGSYS);
            plugin_run_close(run);
            run = NULL;
        }
    } TEST_END
    plugin_run_close(run);
    prt_env_close(&e);
    return failures;
}

static off_t prt_size(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 ? st.st_size : -1;
}

static int prt_case_landlock_files(void)
{
    int failures = 0;
    struct prt_env e;
    struct plugin_run *run = NULL, *ro = NULL;
    bool ready = prt_env_open(&e);
    TEST_CASE("truncating a file outside data.dir is refused and fs.read cannot write") {
        char gen[PRT_HEX], report[1024], dir[PATH_MAX], victim[PATH_MAX], w[PATH_MAX];
        int eacces = 13;
        ASSERT(ready);
        ASSERT(prt_install(&e, "trunc", "truncate", "t1", PRT_FS, gen));
        ASSERT(zcl_path_join(dir, sizeof(dir), e.root, "trunc"));
        ASSERT(zcl_path_join(victim, sizeof(victim), dir, "victim.txt"));
        ASSERT(prt_write(victim, "keep", 4));
        run = prt_open(&e, "trunc");
        ASSERT(run != NULL);
        ASSERT(prt_wait(&run, 1, 0, prt_healthy, NULL, 5000));
        ASSERT(prt_report(&e, "trunc", report, sizeof(report)));
        ASSERT(strstr(report, "truncate_outside=13\n") != NULL);
        ASSERT_EQ(prt_size(victim), (off_t)4);
        ASSERT(prt_install(&e, "ro", "readonly", "r1", "\"fs.read\",\"clock\"", gen));
        ro = prt_open(&e, "ro");
        ASSERT(ro != NULL);
        ASSERT(prt_wait(&ro, 1, 0, prt_exit_code, &eacces, 5000));
        ASSERT(zcl_path_join(dir, sizeof(dir), e.root, "ro"));
        ASSERT(zcl_path_join(w, sizeof(w), dir, "data/w.txt"));
        ASSERT(access(w, F_OK) != 0);
    } TEST_END
    plugin_run_close(run);
    plugin_run_close(ro);
    prt_env_close(&e);
    return failures;
}

static int prt_case_fd_layout(void)
{
    int failures = 0;
    struct prt_env e;
    struct plugin_run *run = NULL;
    bool ready = prt_env_open(&e);
    TEST_CASE("a plugin without fs capabilities gets control and log only") {
        char gen[PRT_HEX];
        int ok = 21;
        ASSERT(ready);
        ASSERT(prt_install(&e, "nofs", "nofs", "n1", "\"clock\"", gen));
        run = prt_open(&e, "nofs");
        ASSERT(run != NULL);
        ASSERT(prt_wait(&run, 1, 0, prt_exit_code, &ok, 5000));
    } TEST_END
    plugin_run_close(run);
    prt_env_close(&e);
    return failures;
}

static int prt_case_permission_update(void)
{
    int failures = 0;
    struct prt_env e;
    struct plugin_run *wide = NULL, *narrow = NULL;
    bool ready = prt_env_open(&e);
    TEST_CASE("a narrowed manifest for the same executable no longer grants writes") {
        char g1[PRT_HEX], g2[PRT_HEX], dir[PATH_MAX], w[PATH_MAX];
        int granted = 0, eacces = EACCES;
        struct plugin_run_info info;
        ASSERT(ready);
        ASSERT(prt_install(&e, "perm", "readonly", "p1", PRT_FS, g1));
        ASSERT(zcl_path_join(dir, sizeof(dir), e.root, "perm"));
        ASSERT(zcl_path_join(w, sizeof(w), dir, "data/w.txt"));
        wide = prt_open(&e, "perm");
        ASSERT(wide != NULL);
        /* last_exit_code starts at 0, so wait for the write itself */
        ASSERT(prt_wait(&wide, 1, 0, prt_file_exists, w, 5000));
        ASSERT(prt_wait(&wide, 1, 0, prt_exit_code, &granted, 5000));
        plugin_run_close(wide);
        wide = NULL;
        ASSERT_EQ(unlink(w), 0);
        ASSERT(prt_install(&e, "perm", "readonly", "p1", "\"fs.read\",\"clock\"", g2));
        ASSERT(strcmp(g1, g2) != 0);
        narrow = prt_open(&e, "perm");
        ASSERT(narrow != NULL);
        ASSERT(prt_wait(&narrow, 1, 0, prt_exit_code, &eacces, 5000));
        plugin_run_info_get(narrow, &info);
        ASSERT_STR_EQ(info.generation, g2);
        ASSERT(access(w, F_OK) != 0);
    } TEST_END
    plugin_run_close(wide);
    plugin_run_close(narrow);
    prt_env_close(&e);
    return failures;
}

static int prt_case_swapped_executable(void)
{
    int failures = 0;
    struct prt_env e;
    struct plugin_run *run = NULL;
    bool ready = prt_env_open(&e);
    TEST_CASE("an executable swapped after the run was opened is refused at start") {
        char gen[PRT_HEX], exe[PATH_MAX];
        struct plugin_run_info info;
        ASSERT(ready);
        ASSERT(prt_install(&e, "swap", "normal", "s1", PRT_FS, gen));
        run = prt_open(&e, "swap");
        ASSERT(run != NULL);
        snprintf(exe, sizeof(exe), "%s/swap/generations/%s/swap", e.root, gen);
        ASSERT_EQ(chmod(exe, 0755), 0);
        ASSERT(prt_write(exe, "evil", 4));
        /* the open-time verification is cached, so the per-launch executable hash refuses it */
        ASSERT_EQ(plugin_run_poll(run), PLUGIN_RUN_ERR_SPAWN);
        plugin_run_info_get(run, &info);
        ASSERT_EQ(info.state, PLUGIN_RUN_STATE_FAILED);
        ASSERT_EQ(info.pid, 0u);
    } TEST_END
    plugin_run_close(run);
    prt_env_close(&e);
    return failures;
}

/* Runs in a forked copy so descriptors 3 to 6 can be arranged freely: the
 * sources of the two extra slots sit in each other's destination (5 and 4). */
static bool prt_slot_byte(int fd, char want)
{
    struct pollfd waiter = {.fd = fd, .events = POLLIN};
    char got = 0;
    return poll(&waiter, 1, 3000) > 0 && read(fd, &got, 1) == 1 && got == want;
}

static int prt_slots_spawn(const char *image, int extra_a, int extra_b)
{
    struct resident_launch_accepted accepted;
    struct resident_launch launch;
    struct resident_receipt receipt;
    char error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    char *envp[] = {NULL};
    int grant = os_sandbox_open_grant(image);
    int high = grant < 0 ? -1 : fcntl(grant, F_DUPFD_CLOEXEC, 16);
    if (high < 0 || !prt_accept(image, &accepted))
        return 20;
    struct os_sandbox_path_rule rule = {.path = image, .allow_read = true,
                                        .allow_execute = true, .has_fd = true, .fd = high};
    struct os_sandbox_profile profile = os_sandbox_plugin_profile(&rule, 1);
    if (!resident_launch_prepare(&launch, image, &accepted, error, sizeof(error)))
        return 21;
    char *argv[] = {(char *)image, "--resident", launch.nonce, NULL};
    launch.extra_fds[0] = extra_a;
    launch.extra_fds[1] = extra_b;
    launch.n_extra_fds = 2;
    launch.null_stdio = true;
    bool ok = resident_launch_spawn_confined(&launch, argv, envp, &profile, &receipt,
                                             error, sizeof(error));
    close(high);
    if (ok)
        (void)resident_launch_cancel(&launch, 500, error, sizeof(error));
    resident_launch_close(&launch);
    return ok ? 0 : 22;
}

static int prt_slots_child(const char *image)
{
    int pa[2], pb[2];
    for (int fd = 3; fd < 128; fd++)
        close(fd);
    if (pipe(pa) != 0 || pipe(pb) != 0) /* 3,4 and 5,6 */
        return 10;
    int ra = fcntl(pa[0], F_DUPFD, 30), rb = fcntl(pb[0], F_DUPFD, 31);
    close(pa[0]);
    close(pb[0]);
    if (ra < 0 || rb < 0 || dup2(pa[1], 5) != 5)
        return 11;
    close(pa[1]);
    if (dup2(pb[1], 4) != 4)
        return 12;
    close(pb[1]);
    int rc = prt_slots_spawn(image, 5, 4); /* slot 4 gets A's pipe, slot 5 B's */
    close(4);
    close(5);
    if (rc != 0)
        return rc;
    return prt_slot_byte(ra, 'A') && prt_slot_byte(rb, 'B') ? 0 : 13;
}

static int prt_case_fd_slots(void)
{
    int failures = 0;
    struct prt_env e;
    bool ready = prt_env_open(&e);
    TEST_CASE("extra descriptors numbered 3 to 6 land in their slots") {
        char image[PATH_MAX];
        size_t len = 0;
        int status = -1;
        unsigned char *img;
        ASSERT(ready);
        img = prt_image("logonly", "l1", &len);
        ASSERT(img != NULL);
        ASSERT(zcl_path_join(image, sizeof(image), e.src, "slots-image"));
        ASSERT(prt_write(image, img, len));
        free(img);
        ASSERT_EQ(chmod(image, 0755), 0);
        fflush(NULL);
        pid_t pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0)
            _exit(prt_slots_child(image));
        ASSERT_EQ(waitpid(pid, &status, 0), pid);
        if (WIFEXITED(status))
            printf("[child code %d] ", WEXITSTATUS(status));
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    } TEST_END
    prt_env_close(&e);
    return failures;
}

static bool prt_call(const char *input_json, struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    bool ok = json_read(&input, input_json, strlen(input_json));
    struct zcl_command_request request = { .input = &input, .view = "normal" };
    zcl_command_reply_init(reply, "zcl.plugin_test.v1");
    if (ok)
        zcl_native_handle_plugin_run(&request, reply);
    json_free(&input);
    return ok;
}

static int prt_case_first_start_refused(void)
{
    int failures = 0;
    struct prt_env e;
    struct plugin_run *run = NULL;
    bool ready = prt_env_open(&e);
    TEST_CASE("an image that cannot be launched confined ends supervision at the first start") {
        static const unsigned char script[] = "#!/bin/sh\nexit 0\n";
        char gen[PRT_HEX];
        struct plugin_run_info info;
        ASSERT(ready);
        ASSERT(prt_publish_bytes(&e, "script", script, sizeof(script) - 1, PRT_FS, gen));
        ASSERT_EQ(plugin_store_switch(e.root, "script", gen), PLUGIN_OK);
        run = prt_open(&e, "script");
        ASSERT(run != NULL);
        ASSERT_EQ(plugin_run_poll(run), PLUGIN_RUN_ERR_SPAWN);
        plugin_run_info_get(run, &info);
        ASSERT_EQ(info.state, PLUGIN_RUN_STATE_FAILED);
        ASSERT_EQ(info.pid, 0u);
        ASSERT(info.detail[0] != '\0');
        ASSERT_EQ(plugin_run_poll(run), PLUGIN_RUN_ERR_FAILED);
    } TEST_END
    plugin_run_close(run);
    prt_env_close(&e);
    return failures;
}

static int prt_case_command(void)
{
    int failures = 0;
    struct prt_env e;
    bool ready = prt_env_open(&e);
    const char *old_home = getenv("HOME");
    TEST_CASE("plugin.run supervises for the given seconds and refuses by name") {
        char gen[PRT_HEX];
        struct zcl_command_reply r;
        const struct zcl_command_spec *s = zcl_command_registry_find(zcl_command_catalog(),
                                                                     "plugin.run", NULL);
        ASSERT(ready);
        ASSERT(s && s->handler == zcl_native_handle_plugin_run);
        ASSERT_EQ(setenv("HOME", e.home, 1), 0);
        ASSERT(prt_install(&e, "alpha", "normal", "a1", PRT_FS, gen));
        ASSERT(prt_call("{\"name\":\"alpha\",\"seconds\":1}", &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "generation")), gen);
        ASSERT(json_get_int(json_get(&r.data, "pings_ok")) >= 1);
        zcl_command_reply_free(&r);
        const char *cli_args[] = {"run", "alpha", "1"};
        ASSERT_EQ(zcl_native_command_main("plugin", cli_args, 3, e.base, 0,
                                         CHAIN_MAIN, true), ZCL_COMMAND_EXIT_OK);
        ASSERT(prt_call("{\"name\":\"nothing\"}", &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_NOT_INSTALLED");
        zcl_command_reply_free(&r);
        ASSERT(prt_install(&e, "net", "normal", "n1", "\"net.server\"", gen));
        ASSERT(prt_call("{\"name\":\"net\",\"seconds\":1}", &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_RUN_CAPABILITY");
        ASSERT(r.error.next_action[0] != '\0');
        zcl_command_reply_free(&r);
        ASSERT(prt_call("{\"name\":\"alpha\",\"seconds\":-4}", &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_ARGUMENT");
        zcl_command_reply_free(&r);
    } TEST_END
    if (old_home)
        setenv("HOME", old_home, 1);
    prt_env_close(&e);
    return failures;
}

/* The launch seam: extra descriptors and null stdio need a confined spawn. */
static bool prt_accept(const char *path, struct resident_launch_accepted *a)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot snap;
    struct sha3_256_ctx ctx;
    unsigned char chunk[4096], digest[32];
    uint64_t offset = 0;
    int64_t got = 1;
    platform_positioned_file_init(&file);
    bool ok = platform_positioned_file_open(&file, path) &&
              platform_positioned_file_snapshot(&file, &snap);
    sha3_256_init(&ctx);
    while (ok && got > 0) {
        got = platform_positioned_file_read(&file, chunk, sizeof(chunk), offset);
        ok = got >= 0;
        if (ok && got > 0)
            sha3_256_write(&ctx, chunk, (size_t)got);
        offset += (uint64_t)(got > 0 ? got : 0);
    }
    platform_positioned_file_close(&file);
    sha3_256_finalize(&ctx, digest);
    for (int i = 0; i < 32; i++)
        snprintf(a->image_sha3_hex + 2 * i, 3, "%02x", digest[i]);
    a->image_volume = snap.volume;
    a->image_low = snap.file_low;
    a->image_high = snap.file_high;
    a->image_size = snap.size;
    return ok;
}

static int prt_case_launch_seam(void)
{
    int failures = 0;
    struct resident_launch launch;
    int pipefd[2] = {-1, -1};
    resident_launch_init(&launch);
    TEST_CASE("extra descriptors are refused without a confined spawn or with a slot clash") {
        struct resident_launch_accepted accepted;
        struct resident_receipt receipt;
        char error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
        char *argv[] = {PRT_FIXTURE, "--resident", "x", NULL};
        char *envp[] = {NULL};
        struct os_sandbox_path_rule rule = {.path = "/", .allow_read = true,
                                            .has_fd = true, .fd = 4};
        struct os_sandbox_profile profile = os_sandbox_plugin_profile(&rule, 1);
        ASSERT_EQ(pipe(pipefd), 0);
        ASSERT(prt_accept(PRT_FIXTURE, &accepted));
        ASSERT(resident_launch_prepare(&launch, PRT_FIXTURE, &accepted, error, sizeof(error)));
        launch.extra_fds[0] = pipefd[1];
        launch.n_extra_fds = 1;
        ASSERT(!resident_launch_spawn(&launch, argv, envp, &receipt, error, sizeof(error)));
        ASSERT(strstr(error, "confined spawn") != NULL);
        ASSERT(!launch.spawned);
        ASSERT(!resident_launch_spawn_confined(&launch, argv, envp, &profile, &receipt,
                                               error, sizeof(error)));
        ASSERT(!launch.spawned);
        launch.n_extra_fds = 0;
        launch.null_stdio = true;
        ASSERT(!resident_launch_spawn(&launch, argv, envp, &receipt, error, sizeof(error)));
        ASSERT(!launch.spawned);
    } TEST_END
    resident_launch_close(&launch);
    if (pipefd[0] >= 0) {
        close(pipefd[0]);
        close(pipefd[1]);
    }
    return failures;
}

static bool prt_log_sanitized(const struct plugin_run_info *i, const void *ctx)
{
    (void)ctx;
    return strcmp(i->last_log, "a?[31m?b?c") == 0;
}

static int prt_case_log_controls(void)
{
    int failures = 0;
    struct prt_env e;
    struct plugin_run *run = NULL;
    bool ready = prt_env_open(&e);
    TEST_CASE("escape, bell and carriage return in a plugin log line arrive as '?'") {
        char gen[PRT_HEX];
        ASSERT(ready);
        ASSERT(prt_install(&e, "logctl", "logctl", "l1", PRT_FS, gen));
        run = prt_open(&e, "logctl");
        ASSERT(run != NULL);
        ASSERT(prt_wait(&run, 1, 0, prt_log_sanitized, NULL, 5000));
    } TEST_END
    plugin_run_close(run);
    prt_env_close(&e);
    return failures;
}

static int prt_case_signal_state(void)
{
    int failures = 0;
    struct prt_env e;
    struct plugin_run *run = NULL;
    sigset_t blocked, saved;
    struct sigaction ign = {.sa_handler = SIG_IGN}, old_pipe, old_int;
    bool ready = prt_env_open(&e);
    sigemptyset(&ign.sa_mask);
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGUSR1);
    sigaddset(&blocked, SIGUSR2);
    sigaddset(&blocked, SIGALRM);
    sigaddset(&blocked, SIGHUP);
    TEST_CASE("a plugin starts with a clean signal mask from a blocking, ignoring parent") {
        char gen[PRT_HEX], text[512];
        ASSERT(ready);
        ASSERT(prt_install(&e, "sigs", "sigstate", "g1", PRT_FS, gen));
        pthread_sigmask(SIG_BLOCK, &blocked, &saved);
        sigaction(SIGPIPE, &ign, &old_pipe);
        sigaction(SIGINT, &ign, &old_int);
        run = prt_open(&e, "sigs");
        bool got = run != NULL && prt_wait(&run, 1, 0, prt_healthy, NULL, 5000) &&
                   prt_report(&e, "sigs", text, sizeof(text));
        pthread_sigmask(SIG_SETMASK, &saved, NULL);
        sigaction(SIGPIPE, &old_pipe, NULL);
        sigaction(SIGINT, &old_int, NULL);
        ASSERT(got);
        ASSERT(strstr(text, "sigblocked=0\n") != NULL);
        ASSERT(strstr(text, "sigpipe=0\n") != NULL);
        ASSERT(strstr(text, "sigint=0\n") != NULL);
        ASSERT(strstr(text, "pdeathsig=9\n") != NULL);
    } TEST_END
    plugin_run_close(run);
    prt_env_close(&e);
    return failures;
}

static bool prt_status_lost(const struct plugin_run_info *i, const void *ctx)
{
    (void)ctx;
    return i->state != PLUGIN_RUN_STATE_RUNNING && strstr(i->detail, "exit status lost") != NULL;
}

static int prt_case_status_lost(void)
{
    int failures = 0;
    struct prt_env e;
    struct plugin_run *run = NULL;
    struct sigaction ign = {.sa_handler = SIG_IGN}, old;
    bool ready = prt_env_open(&e);
    sigemptyset(&ign.sa_mask);
    TEST_CASE("an exit status the kernel discarded is reported as lost, not as a clean exit") {
        char gen[PRT_HEX];
        struct plugin_run_info info;
        ASSERT(ready);
        ASSERT(prt_install(&e, "lost", "nofs", "x1", "\"clock\"", gen));
        sigaction(SIGCHLD, &ign, &old);
        run = prt_open(&e, "lost");
        bool seen = run != NULL && prt_wait(&run, 1, 0, prt_status_lost, NULL, 5000);
        sigaction(SIGCHLD, &old, NULL);
        ASSERT(seen);
        plugin_run_info_get(run, &info);
        ASSERT_EQ(info.last_exit_code, -1);
        ASSERT_EQ(info.last_exit_signal, 0);
    } TEST_END
    plugin_run_close(run);
    prt_env_close(&e);
    return failures;
}

static int prt_case_hash_mismatch(void)
{
    int failures = 0;
    struct prt_env e;
    struct plugin_run *run = NULL;
    bool ready = prt_env_open(&e);
    TEST_CASE("an executable whose bytes differ from the signed SHA3-512 is never started") {
        char gen[PRT_HEX];
        struct plugin_run_info info;
        ASSERT(ready);
        ASSERT(prt_install(&e, "hmis", "normal", "h1", PRT_FS, gen));
        plugin_run_test_corrupt_signed_hash(true);
        run = prt_open(&e, "hmis");
        ASSERT(run != NULL);
        enum plugin_run_status st = plugin_run_poll(run);
        plugin_run_test_corrupt_signed_hash(false);
        ASSERT_EQ(st, PLUGIN_RUN_ERR_SPAWN);
        plugin_run_info_get(run, &info);
        ASSERT_EQ(info.pid, 0u);
        ASSERT_EQ(info.state, PLUGIN_RUN_STATE_FAILED);
        ASSERT(strstr(info.detail, "image not accepted") != NULL);
    } TEST_END
    plugin_run_close(run);
    prt_env_close(&e);
    return failures;
}

int test_plugin_run(void)
{
    int failures = 0;
    printf("\n=== Plugin run tests ===\n");
    TEST_CASE("the kernel provides Landlock ABI 3 and seccomp, which the group needs") {
        ASSERT(os_sandbox_landlock_abi() >= 3);
        ASSERT(os_sandbox_seccomp_supported());
    } TEST_END
    if (failures)
        return failures;
    failures += prt_case_descriptors();
    failures += prt_case_confinement();
    failures += prt_case_forbidden_calls();
    failures += prt_case_landlock_files();
    failures += prt_case_fd_layout();
    failures += prt_case_permission_update();
    failures += prt_case_swapped_executable();
    failures += prt_case_fd_slots();
    failures += prt_case_kill_backoff();
    failures += prt_case_verify_cache();
    failures += prt_case_cached_exe_hash();
    failures += prt_case_keys_aba();
    failures += prt_case_cached_unsafe_dir("a remembered generation is refused once its directory is group-writable", "udg", false);
    failures += prt_case_cached_unsafe_dir("a remembered generation is refused once the generations directory is group-writable", "udd", true);
    failures += prt_case_hung_ping();
    failures += prt_case_reload();
    failures += prt_case_reload_refused();
    failures += prt_case_crash_loop();
    failures += prt_case_crash_no_fallback();
    failures += prt_case_refusals();
    failures += prt_case_first_start_refused();
    failures += prt_case_command();
    failures += prt_case_launch_seam();
    failures += prt_case_log_controls();
    failures += prt_case_signal_state();
    failures += prt_case_status_lost();
    failures += prt_case_hash_mismatch();
    return failures;
}
#endif
