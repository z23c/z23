/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_fastobj_carrier — the WIRE lane slice-2 offline proof
 * (docs/work/WIRE_COMPILE_CACHE.md): a builder's cached objects plus
 * sidecars travel as an ORDINARY content.v2 package to a second cache
 * directory, and the second node builds with ZERO compiler spawns and
 * byte-identical receipt bytes.
 *
 * The journey, all offline (no daemon, no network):
 *   1. prepare the tiny-lines fixture package (contexts/commons/modules/vcs only — the
 *      candidate proof action needs no signed release),
 *   2. confined candidate build #1 with --fast-cache=cacheA (cold: the
 *      gcc compile really runs, the cache fills),
 *   3. export cacheA into store nodeA as one content.v2 carrier
 *      (zcl-fastobj-carrier.v1/objects/<key>.o|.json),
 *   4. classify the exported carrier in nodeA: the public shape is
 *      fastobj-carrier, so a -packagehost=1 node may announce and serve
 *      it (the serve-time proof is the consumer's own admit proof,
 *      re-derived read-only from stored bytes),
 *   5. re-export into a THIRD store: the carrier root must be identical
 *      (deterministic root for identical object bytes),
 *   6. fetch the carrier root store-to-store into nodeB — the offline
 *      stand-in for the swarm wire, same verify-before-store admission,
 *   7. admit from nodeB into a FRESH cacheB (every entry re-verified),
 *   8. re-export cacheB into a FOURTH store: same root again — cacheB
 *      is byte-identical to cacheA through the whole round trip,
 *   9. confined candidate build #2 with --fast-cache=cacheB: every
 *      eligible TU is a HIT (misses == 0 — zero gcc compile spawns; the
 *      -E identity probe still runs by design, it IS the key input),
 *  10. build-report #2 is byte-identical to build-report #1 (memcmp of
 *      the ZCLBLD receipt wires) and both receipts hash to the same id.
 *  10. the tested standard receipt really ran the fixture's tests, and its
 *      flags string still claims asan,ubsan=clean (both outcomes PASS).
 *  11. the testless standard-profile refusal, both sides: a tests/-less
 *      copy of the fixture is REFUSED (exit 6) in the evidence shape and
 *      BUILDS with --allow-testless-standard (the reproduce shape), its
 *      receipt honestly recording test_ran=false / BUILD_PASS and flags
 *      asan,ubsan=not-run.
 *  12. a use-after-free fixture copy under the reproduce shape still EMITS
 *      (installable TEST_PASS — the receipt is evidence, not a gate), but
 *      its flags say asan,ubsan=findings, never clean.
 *
 * Refusal legs (no builds): a torn pair, a sidecar whose object_sha3
 * lies about its object, an entry filed under the wrong key, and a
 * hand-built carrier whose sidecar does not hash to its own filename
 * all refuse — export at the source, admit at the destination — and the
 * public-shape gate refuses the lying carrier a servable shape.
 *
 * The candidate lane forks the package verifier beside this binary —
 * it MUST exist (make dev-bin); a missing binary is a loud failure,
 * never a silent skip. */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

#include "base/hex.h"
#include "core/uint256.h"
#include "platform/os_proc.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "sha3/sha3.h"
#include "vcs/fastobj.h"
#include "vcs/fastobj_carrier.h"
#include "vcs/package_build.h"
#include "vcs/package_content.h"
#include "vcs/package_manifest.h"
#include "vcs/package_prepare.h"
#include "vcs/package_public_shape.h"
#include "vcs/package_store.h"

#if !defined(_WIN32)

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define FC_CHECK(name, expr) do {                                       \
    if (expr) { printf("  fastobj_carrier: %s... OK\n", (name)); }      \
    else { printf("  fastobj_carrier: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* ── tiny filesystem helpers (same shape as test_zcode_add) ─────────── */

static bool fcw_mkdir_p(const char *path)
{
    char buf[4096];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(buf))
        return false;
    memcpy(buf, path, len + 1);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0700) != 0 && errno != EEXIST) {
            *p = '/';
            return false;
        }
        *p = '/';
    }
    return mkdir(buf, 0700) == 0 || errno == EEXIST;
}

static bool fcw_rm_rf(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return errno == ENOENT;
    if (!S_ISDIR(st.st_mode))
        return unlink(path) == 0;
    DIR *d = opendir(path);
    if (!d)
        return false;
    struct dirent *e;
    bool ok = true;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char child[4096];
        if (snprintf(child, sizeof(child), "%s/%s", path, e->d_name) >=
            (int)sizeof(child)) {
            ok = false;
            continue;
        }
        ok = fcw_rm_rf(child) && ok;
    }
    closedir(d);
    return rmdir(path) == 0 && ok;
}

static bool fcw_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static bool fcw_write_file(const char *path, const void *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = len == 0 || fwrite(data, 1, len, f) == len;
    if (fclose(f) != 0)
        ok = false;
    return ok;
}

static uint8_t *fcw_read_file(const char *path, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    struct stat st;
    if (fstat(fileno(f), &st) != 0 || st.st_size < 0 ||
        (uint64_t)st.st_size > (uint64_t)cap) {
        fclose(f);
        return NULL;
    }
    size_t n = (size_t)st.st_size;
    uint8_t *buf = malloc(n ? n : 1u);
    if (!buf || (n && fread(buf, 1, n, f) != n)) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len = n;
    return buf;
}

/* Recursive copy via cp -r — the same subprocess shape the package
 * factory selftest uses for the fixture. */
static bool fcw_copy_tree(const char *src, const char *dst)
{
    char argv_buf[4200];
    if (snprintf(argv_buf, sizeof(argv_buf), "cp -r %s %s", src, dst) >=
        (int)sizeof(argv_buf))
        return false;
    char *argv[] = {(char *)"cp", (char *)"-r", (char *)src, (char *)dst,
                    NULL};
    (void)argv_buf;
    pid_t pid = fork();
    if (pid < 0)
        return false;
    if (pid == 0) {
        execvp("cp", argv);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid)
        return false;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* ── the confined candidate build ───────────────────────────────────── */

/* The package verifier ships beside this binary (never from PATH). */
static bool fcw_worker_path(char *out, size_t cap)
{
    char exe[4096];
    if (!os_proc_exe_path(exe, sizeof(exe)))
        return false;
    char *slash = strrchr(exe, '/');
    if (!slash)
        return false;
    *slash = '\0';
    static const char *const names[] = {
        "zclassic23-package-verify-dev",
        "zclassic23-package-verify",
    };
    for (size_t pass = 0; pass < 2u; pass++) {
        for (size_t i = 0; i < 2u; i++) {
            int w = snprintf(out, cap, "%s/%s",
                             pass == 0 ? exe : "build/bin", names[i]);
            if (w > 0 && (size_t)w < cap && fcw_exists(out))
                return true;
        }
    }
    return false;
}

struct fcw_build_result {
    bool ok;
    int exit_code;
    unsigned long long hits;
    unsigned long long misses;
    bool saw_refusal;
    char first_line[256];
    char last_line[256];
};

/* Spawn the verifier in candidate proof mode with a fast cache, capture
 * merged stdout/stderr, and parse the fast-cache counters line. When
 * allow_testless is true the run passes --allow-testless-standard (the
 * reproduce track's opt-out of the evidence-track testless refusal). */
static void fcw_candidate_build(const char *worker, const char *root_hex,
                                const char *pkg_abs, const char *recipe_abs,
                                const char *emit_dir, const char *lock_hex,
                                const char *cache_dir, bool allow_testless,
                                struct fcw_build_result *out)
{
    memset(out, 0, sizeof(*out));
    out->exit_code = -1;
    char source_arg[4200], recipe_arg[4200], emit_arg[4096],
         lock_arg[128], fast_arg[4096], name_arg[128], cpu_arg[64];
    if (snprintf(source_arg, sizeof(source_arg),
                 "--zbuild-package-source=%s", pkg_abs) >=
            (int)sizeof(source_arg) ||
        snprintf(recipe_arg, sizeof(recipe_arg),
                 "--zbuild-package-recipe=%s", recipe_abs) >=
            (int)sizeof(recipe_arg) ||
        snprintf(emit_arg, sizeof(emit_arg), "--emit=%s", emit_dir) >=
            (int)sizeof(emit_arg) ||
        snprintf(lock_arg, sizeof(lock_arg), "--lock-root=%s", lock_hex) >=
            (int)sizeof(lock_arg) ||
        snprintf(fast_arg, sizeof(fast_arg), "--fast-cache=%s",
                 cache_dir) >= (int)sizeof(fast_arg) ||
        snprintf(name_arg, sizeof(name_arg),
                 "--zbuild-package-name=fixture/tiny-lines") >=
            (int)sizeof(name_arg) ||
        snprintf(cpu_arg, sizeof(cpu_arg),
                 "--zbuild-package-max-cpu-seconds=120") >=
            (int)sizeof(cpu_arg))
        return;
    const char *argv[] = {worker,       root_hex,     source_arg,
                          recipe_arg,   name_arg,
                          "--zbuild-package-profile=standard",
                          cpu_arg,      emit_arg,     lock_arg,
                          fast_arg,
                          allow_testless ? "--allow-testless-standard"
                                         : "--require-full-isolation",
                          allow_testless ? "--require-full-isolation" : NULL,
                          NULL};
    int fds[2];
    if (pipe(fds) != 0)
        return;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return;
    }
    if (pid == 0) {
        if (dup2(fds[1], STDOUT_FILENO) < 0 ||
            dup2(fds[1], STDERR_FILENO) < 0)
            _exit(126);
        close(fds[0]);
        close(fds[1]);
        execv(worker, (char *const *)argv);
        _exit(127);
    }
    close(fds[1]);
    /* Drain until EOF, a 1 MiB cap, or 300 s of silence — whichever
     * comes first. */
    size_t cap = 1024u * 1024u, len = 0;
    char *text = malloc(cap);
    if (text) {
        int idle = 0;
        while (len + 1u < cap && idle < 300) {
            struct pollfd pfd = {fds[0], POLLIN, 0};
            int pr = poll(&pfd, 1, 1000);
            if (pr < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }
            if (pr == 0) {
                idle++;
                continue;
            }
            ssize_t got = read(fds[0], text + len, cap - len - 1u);
            if (got < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }
            if (got == 0)
                break; /* EOF */
            len += (size_t)got;
            idle = 0;
        }
        text[len] = '\0';
    }
    /* Reap: up to 60 s past EOF for the exit syscall, then SIGKILL. */
    int status = 0;
    bool reaped = false, killed = false;
    for (int i = 0; i < 60 && !reaped; i++) {
        if (waitpid(pid, &status, WNOHANG) == pid) {
            reaped = true;
            break;
        }
        sleep(1);
    }
    if (!reaped) {
        kill(pid, SIGKILL);
        killed = true;
        (void)waitpid(pid, &status, 0);
    }
    close(fds[0]);
    out->exit_code = !killed && WIFEXITED(status) ? WEXITSTATUS(status)
                                                  : -1;
    out->ok = !killed && out->exit_code == 0;
    if (text) {
        snprintf(out->first_line, sizeof(out->first_line), "%.255s", text);
        const char *end = text + len;
        if (end > text && end[-1] == '\n')
            end--;
        const char *tail = end;
        while (tail > text && tail[-1] != '\n')
            tail--;
        snprintf(out->last_line, sizeof(out->last_line), "%.*s",
                 (int)(end - tail), tail);
        out->saw_refusal =
            strstr(text, "zbuild-package-standard-refused=1") != NULL;
        char *line = strstr(text, "zbuild-package-fast-cache=v1");
        if (line)
            (void)sscanf(line,
                         "zbuild-package-fast-cache=v1 hits=%llu "
                         "misses=%llu", &out->hits, &out->misses);
        free(text);
    }
}

/* ── refusal-leg helpers ────────────────────────────────────────────── */

/* Find any one complete cache entry key (the first <62 hex>.o member the
 * directory walk meets). */
static bool fcw_first_entry(const char *cache_dir, char key_out[65])
{
    char objects[4096];
    if (snprintf(objects, sizeof(objects), "%s/objects", cache_dir) >=
        (int)sizeof(objects))
        return false;
    DIR *shards = opendir(objects);
    if (!shards)
        return false;
    struct dirent *sh;
    bool found = false;
    while (!found && (sh = readdir(shards)) != NULL) {
        if (strlen(sh->d_name) != 2)
            continue;
        char shard[4096];
        if (snprintf(shard, sizeof(shard), "%s/%s", objects, sh->d_name) >=
            (int)sizeof(shard))
            continue;
        DIR *d = opendir(shard);
        if (!d)
            continue;
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (strlen(e->d_name) == 64 &&
                strcmp(e->d_name + 62, ".o") == 0) {
                key_out[0] = sh->d_name[0];
                key_out[1] = sh->d_name[1];
                memcpy(key_out + 2, e->d_name, 62);
                key_out[64] = '\0';
                found = true;
                break;
            }
        }
        closedir(d);
    }
    closedir(shards);
    return found;
}

/* Bytes-forward substring search over a non-NUL-terminated buffer. */
static const char *fcw_find(const uint8_t *hay, size_t len,
                            const char *needle)
{
    size_t n = strlen(needle);
    if (len < n)
        return NULL;
    for (size_t i = 0; i + n <= len; i++) {
        if (memcmp(hay + i, needle, n) == 0)
            return (const char *)(hay + i);
    }
    return NULL;
}

static int test_fastobj_carrier_platform_arm(void)
{
    int failures = 0;
    printf("fastobj_carrier: object-set carrier, offline proof\n");

    /* Everything the done: cleanup touches is declared and initialized
     * BEFORE the first goto done (C permits jumping over declarations;
     * freeing a skipped initializer would be undefined). */
    char err[512] = "";
    struct vcs_package_prepared prep;
    vcs_package_prepared_init(&prep);
    struct vcs_package_prepared prepT;
    vcs_package_prepared_init(&prepT);
    struct vcs_package_prepared prepF;
    vcs_package_prepared_init(&prepF);
    struct vcs_fastobj_carrier_stats stA, stC, stF, stAd, stD, stRef;
    memset(&stA, 0, sizeof(stA));
    memset(&stC, 0, sizeof(stC));
    memset(&stF, 0, sizeof(stF));
    memset(&stAd, 0, sizeof(stAd));
    memset(&stD, 0, sizeof(stD));
    memset(&stRef, 0, sizeof(stRef));
    uint8_t rootA[32] = {0}, rootC[32] = {0}, rootD[32] = {0}, rootL[32] = {0};
    struct vcs_package_store *nodeA = NULL, *nodeB = NULL, *nodeC = NULL,
                             *nodeD = NULL, *storeR = NULL;
    size_t r1_len = 0, r2_len = 0, rT_len = 0, rF_len = 0;
    uint8_t *r1 = NULL, *r2 = NULL, *rT = NULL, *rF = NULL;

    /* The confined worker ships beside this binary — never from PATH. */
    char worker[4096];
    bool have_worker = fcw_worker_path(worker, sizeof(worker));
    FC_CHECK("package verifier beside the test binary (make dev-bin)",
             have_worker);
    char cwd[3072];
    char base[4096];
    bool base_ok = getcwd(cwd, sizeof(cwd)) != NULL &&
        snprintf(base, sizeof(base), "%s/test-tmp/fastobj_carrier_%ld",
                 cwd, (long)getpid()) < (int)sizeof(base);
    if (!base_ok || !have_worker) {
        printf("fastobj_carrier: FAIL (setup)\n");
        return 1;
    }
    (void)fcw_rm_rf(base);
    if (!fcw_mkdir_p(base)) {
        printf("fastobj_carrier: FAIL (scratch %s)\n", base);
        return 1;
    }

    char pkg[4096], cacheA[4096], cacheB[4096], emit1[4096], emit2[4096],
         recipe_path[4096], dirA[4096], dirB[4096], dirC[4096], dirD[4096],
         dirR[4096];
    bool paths_ok =
        snprintf(pkg, sizeof(pkg), "%s/pkg", base) < (int)sizeof(pkg) &&
        snprintf(cacheA, sizeof(cacheA), "%s/cacheA", base) <
            (int)sizeof(cacheA) &&
        snprintf(cacheB, sizeof(cacheB), "%s/cacheB", base) <
            (int)sizeof(cacheB) &&
        snprintf(emit1, sizeof(emit1), "%s/emit1", base) <
            (int)sizeof(emit1) &&
        snprintf(emit2, sizeof(emit2), "%s/emit2", base) <
            (int)sizeof(emit2) &&
        snprintf(recipe_path, sizeof(recipe_path), "%s/recipe.wire", base) <
            (int)sizeof(recipe_path) &&
        snprintf(dirA, sizeof(dirA), "%s/nodeA", base) < (int)sizeof(dirA) &&
        snprintf(dirB, sizeof(dirB), "%s/nodeB", base) < (int)sizeof(dirB) &&
        snprintf(dirC, sizeof(dirC), "%s/nodeC", base) < (int)sizeof(dirC) &&
        snprintf(dirD, sizeof(dirD), "%s/nodeD", base) < (int)sizeof(dirD) &&
        snprintf(dirR, sizeof(dirR), "%s/storeR", base) < (int)sizeof(dirR);
    FC_CHECK("scratch paths laid out", paths_ok);
    if (!paths_ok)
        goto done;

    /* 1. prepare the tiny-lines fixture (contexts/commons/modules/vcs only — the candidate
     * proof action needs no signed release). */
    FC_CHECK("tiny-lines fixture copied to scratch",
             fcw_copy_tree("tests/harness/fixtures/zcode/tiny-lines", pkg));
    struct vcs_package_prepare_options opts;
    memset(&opts, 0, sizeof(opts));
    opts.dir = pkg;
    /* The release layer validates the publisher pubkey as a compressed
     * curve point, so derive a real one (the test_zcode_add idiom). */
    struct privkey sk;
    struct pubkey pk;
    memset(sk.vch, 0x11, 32);
    sk.fValid = true;
    sk.fCompressed = true;
    bool have_pk = privkey_get_pubkey(&sk, &pk);
    FC_CHECK("publisher pubkey derived for prepare", have_pk);
    if (!have_pk)
        goto done;
    memcpy(opts.publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    opts.publisher_sequence = 1;
    char prep_detail[512] = "";
    enum vcs_package_prepare_error prc =
        vcs_package_prepare(&opts, &prep, prep_detail, sizeof(prep_detail));
    FC_CHECK("package prepared (root, recipe, lock derived)",
             prc == VCS_PACKAGE_PREPARE_OK);
    if (prc != VCS_PACKAGE_PREPARE_OK)
        printf("    prepare: %s\n", prep_detail);
    char root_hex[65] = "", lock_hex[65] = "";
    zcl_hex_encode(prep.package_root, 32, root_hex);
    zcl_hex_encode(prep.lock_root, 32, lock_hex);
    FC_CHECK("recipe wire written for the worker",
             prc == VCS_PACKAGE_PREPARE_OK &&
                 fcw_write_file(recipe_path, prep.recipe_wire,
                                prep.recipe_wire_len));
    if (prc != VCS_PACKAGE_PREPARE_OK)
        goto done;

#ifdef __APPLE__
    /* Carrier production starts by executing fetched package source. Darwin
     * has no Landlock/seccomp equivalent, so the public contract is the
     * named fail-closed refusal, not a degraded cache artifact. */
    struct fcw_build_result refusal;
    fcw_candidate_build(worker, root_hex, pkg, recipe_path, emit1, lock_hex,
                        cacheA, false, &refusal);
    FC_CHECK("Darwin refuses carrier production without full isolation",
             !refusal.ok && refusal.exit_code == 4 &&
                 strstr(refusal.first_line, "offers no Landlock") != NULL);
    if (refusal.ok || refusal.exit_code != 4 ||
        strstr(refusal.first_line, "offers no Landlock") == NULL)
        printf("    refusal exit %d: %.200s\n", refusal.exit_code,
               refusal.first_line);
    goto done;
#endif

    /* 2. candidate build #1 on a COLD cacheA: the compile really runs. */
    struct fcw_build_result run1, run2;
    memset(&run1, 0, sizeof(run1));
    memset(&run2, 0, sizeof(run2));
    fcw_candidate_build(worker, root_hex, pkg, recipe_path, emit1, lock_hex,
                        cacheA, false, &run1);
    FC_CHECK("candidate build #1 (cold cacheA) succeeded", run1.ok);
    if (!run1.ok)
        printf("    build #1 exit %d: %.200s\n", run1.exit_code,
               run1.first_line);
    FC_CHECK("build #1 really compiled (misses >= 1, hits == 0)",
             run1.ok && run1.misses >= 1u && run1.hits == 0u);
    printf("    build #1: hits=%llu misses=%llu\n", run1.hits, run1.misses);
    if (!run1.ok)
        goto done;

    /* 3. export cacheA into store nodeA as ONE content.v2 carrier. */
    nodeA = vcs_package_store_open(dirA, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    bool expA = nodeA != NULL && vcs_fastobj_carrier_export(
                                    cacheA, nodeA, rootA, &stA, err,
                                    sizeof(err));
    FC_CHECK("cacheA exported as one content.v2 carrier", expA);
    if (!expA)
        printf("    export: %s\n", err);
    FC_CHECK("carrier entries == build #1 misses",
             expA && stA.entries == (uint32_t)run1.misses);
    FC_CHECK("carrier files are object+sidecar pairs",
             expA && stA.files == 2u * stA.entries);
    FC_CHECK("carrier carries real object bytes",
             expA && stA.object_bytes > 0u);
    if (!expA)
        goto done;

    /* 4. the exported carrier has a public shape: a -packagehost=1 node
     *    may announce and serve it, because the serve-time proof is the
     *    consumer's own admit proof re-derived read-only from the store. */
    struct vcs_package_public_verdict shape_v;
    enum vcs_package_public_shape pub =
        vcs_package_public_shape_classify(nodeA, rootA, &shape_v);
    FC_CHECK("exported carrier classifies as fastobj-carrier",
             pub == VCS_PACKAGE_PUBLIC_FASTOBJ_CARRIER);
    FC_CHECK("the carrier rule is its shape string",
             shape_v.rule != NULL &&
                 strcmp(shape_v.rule,
                        vcs_package_public_shape_string(pub)) == 0);
    FC_CHECK("fastobj carrier is not licensed content",
             !vcs_package_public_shape_licensed(pub));
    FC_CHECK("read-only carrier verify passes on the exporter's store",
             vcs_fastobj_carrier_verify(nodeA, rootA, err, sizeof(err)));

    /* 5. re-export into a THIRD store: the root must not move. */
    nodeC = vcs_package_store_open(dirC, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    bool expC = nodeC != NULL && vcs_fastobj_carrier_export(
                                     cacheA, nodeC, rootC, &stC, err,
                                     sizeof(err));
    FC_CHECK("re-export into a third store succeeded", expC);
    if (!expC)
        printf("    re-export: %s\n", err);
    FC_CHECK("the carrier root is deterministic (same cache, same root)",
             expC && memcmp(rootA, rootC, 32) == 0);

    /* 6. fetch store-to-store: the offline stand-in for the swarm wire. */
    nodeB = vcs_package_store_open(dirB, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    bool fetched = nodeB != NULL && vcs_fastobj_carrier_fetch(
                                        nodeB, nodeA, rootA, &stF, err,
                                        sizeof(err));
    FC_CHECK("carrier fetched store-to-store into nodeB", fetched);
    if (!fetched)
        printf("    fetch: %s\n", err);
    FC_CHECK("fetched carrier carries the same entries",
             fetched && stF.entries == stA.entries);

    /* 7. admit nodeB's carrier into a FRESH cacheB. */
    bool admitted = fetched && vcs_fastobj_carrier_admit(
                                   cacheB, nodeB, rootA, &stAd, err,
                                   sizeof(err));
    FC_CHECK("carrier admitted into a fresh cacheB", admitted);
    if (!admitted)
        printf("    admit: %s\n", err);
    FC_CHECK("cacheB holds every carried entry",
             admitted && stAd.entries == stA.entries);

    /* 8. re-export cacheB into a FOURTH store: same root again. */
    nodeD = vcs_package_store_open(dirD, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    bool expD = nodeD != NULL && vcs_fastobj_carrier_export(
                                     cacheB, nodeD, rootD, &stD, err,
                                     sizeof(err));
    FC_CHECK("cacheB re-exported into a fourth store", expD);
    if (!expD)
        printf("    re-export cacheB: %s\n", err);
    FC_CHECK("round-trip root identical (cacheB bytes == cacheA bytes)",
             expD && memcmp(rootA, rootD, 32) == 0);

    /* 9. candidate build #2 on cacheB: ZERO compiler spawns. */
    fcw_candidate_build(worker, root_hex, pkg, recipe_path, emit2, lock_hex,
                        cacheB, false, &run2);
    FC_CHECK("candidate build #2 (warm cacheB) succeeded", run2.ok);
    if (!run2.ok)
        printf("    build #2 exit %d: %.200s\n", run2.exit_code,
               run2.first_line);
    printf("    build #2: hits=%llu misses=%llu\n", run2.hits, run2.misses);
    FC_CHECK("build #2 spawned ZERO compilers (misses == 0)",
             run2.ok && run2.misses == 0u);
    FC_CHECK("build #2 hit every entry build #1 missed",
             run2.ok && run2.hits == run1.misses);

    /* 10. the ZCLBLD receipts are byte-identical. */
    char report1[4096], report2[4096];
    bool got_reports =
        snprintf(report1, sizeof(report1), "%s/build-report", emit1) <
            (int)sizeof(report1) &&
        snprintf(report2, sizeof(report2), "%s/build-report", emit2) <
            (int)sizeof(report2);
    if (got_reports) {
        r1 = fcw_read_file(report1, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES,
                           &r1_len);
        r2 = fcw_read_file(report2, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES,
                           &r2_len);
    }
    FC_CHECK("both ZCLBLD build-reports emitted", r1 != NULL && r2 != NULL);
    FC_CHECK("build-report #2 is byte-identical to #1",
             r1 && r2 && r1_len == r2_len && memcmp(r1, r2, r1_len) == 0);
    struct vcs_package_build_receipt rec1, rec2;
    uint8_t id1[32] = {0}, id2[32] = {0};
    bool ids_ok = r1 && r2 &&
        vcs_package_build_parse(r1, r1_len, &rec1) == VCS_PACKAGE_BUILD_OK &&
        vcs_package_build_parse(r2, r2_len, &rec2) == VCS_PACKAGE_BUILD_OK &&
        vcs_package_build_id(&rec1, id1) == VCS_PACKAGE_BUILD_OK &&
        vcs_package_build_id(&rec2, id2) == VCS_PACKAGE_BUILD_OK;
    FC_CHECK("both receipts parse and hash to the same id",
             ids_ok && memcmp(id1, id2, 32) == 0);

    /* 10. the tested path stays honest: receipt #1 really ran the
     * fixture's declared tests under the standard profile, and its flags
     * string still claims "clean" — both sanitizer outcomes were PASS. */
    FC_CHECK("tested standard receipt really ran its tests",
             ids_ok && rec1.test_ran &&
                 rec1.result_class == VCS_PACKAGE_BUILD_RESULT_TEST_PASS);
    FC_CHECK("tested standard receipt flags still claim asan,ubsan=clean",
             ids_ok && strstr(rec1.flags, "asan,ubsan=clean") != NULL);

    /* 11. the testless standard-profile refusal, both sides. A TESTLESS
     * copy of the fixture (tests/ dropped, nothing else changed) under
     * the standard profile is REFUSED with exit 6 in the evidence shape
     * (no opt-out flag — the build fabric / factory candidate shape), and
     * BUILDS with --allow-testless-standard (the reproduce track's
     * opt-out), its receipt recording the testless facts honestly:
     * test_ran=false, result_class=BUILD_PASS, still installable. */
    char pkgT[4096], recipeT_path[4096], emitT1[4096], emitT2[4096],
         cacheT[4096], testsT[4096];
    bool pathsT_ok =
        snprintf(pkgT, sizeof(pkgT), "%s/pkgT", base) < (int)sizeof(pkgT) &&
        snprintf(recipeT_path, sizeof(recipeT_path), "%s/recipeT.wire",
                 base) < (int)sizeof(recipeT_path) &&
        snprintf(emitT1, sizeof(emitT1), "%s/emitT1", base) <
            (int)sizeof(emitT1) &&
        snprintf(emitT2, sizeof(emitT2), "%s/emitT2", base) <
            (int)sizeof(emitT2) &&
        snprintf(cacheT, sizeof(cacheT), "%s/cacheT", base) <
            (int)sizeof(cacheT) &&
        snprintf(testsT, sizeof(testsT), "%s/tests", pkgT) <
            (int)sizeof(testsT);
    bool testless_ready = pathsT_ok &&
        fcw_copy_tree("tests/harness/fixtures/zcode/tiny-lines", pkgT) &&
        fcw_rm_rf(testsT);
    struct vcs_package_prepare_options optsT;
    memset(&optsT, 0, sizeof(optsT));
    optsT.dir = pkgT;
    memcpy(optsT.publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    optsT.publisher_sequence = 1;
    char prepT_detail[512] = "";
    enum vcs_package_prepare_error prcT = VCS_PACKAGE_PREPARE_ERR_IO;
    if (testless_ready)
        prcT = vcs_package_prepare(&optsT, &prepT, prepT_detail,
                                   sizeof(prepT_detail));
    char rootT_hex[65] = "", lockT_hex[65] = "";
    if (prcT == VCS_PACKAGE_PREPARE_OK) {
        zcl_hex_encode(prepT.package_root, 32, rootT_hex);
        zcl_hex_encode(prepT.lock_root, 32, lockT_hex);
    }
    testless_ready =
        testless_ready && prcT == VCS_PACKAGE_PREPARE_OK &&
        fcw_write_file(recipeT_path, prepT.recipe_wire,
                       prepT.recipe_wire_len);
    FC_CHECK("testless fixture variant (tests/ dropped) prepared",
             testless_ready);
    if (!testless_ready && prcT != VCS_PACKAGE_PREPARE_OK)
        printf("    prepare testless: %s\n", prepT_detail);
    if (testless_ready) {
        struct fcw_build_result tref, tok;
        memset(&tref, 0, sizeof(tref));
        memset(&tok, 0, sizeof(tok));
        fcw_candidate_build(worker, rootT_hex, pkgT, recipeT_path, emitT1,
                            lockT_hex, cacheT, false, &tref);
        FC_CHECK("evidence-shape standard run of a testless package "
                 "refuses (exit 6 + refusal line)",
                 tref.exit_code == 6 && tref.saw_refusal);
        if (!(tref.exit_code == 6 && tref.saw_refusal))
            printf("    testless refuse: exit %d: %.200s\n",
                   tref.exit_code, tref.first_line);
        fcw_candidate_build(worker, rootT_hex, pkgT, recipeT_path, emitT2,
                            lockT_hex, cacheT, true, &tok);
        FC_CHECK("reproduce-shape standard run of a testless package "
                 "builds", tok.ok);
        if (!tok.ok)
            printf("    testless allow: exit %d: %.200s\n", tok.exit_code,
                   tok.first_line);
        char reportT[4096];
        if (tok.ok &&
            snprintf(reportT, sizeof(reportT), "%s/build-report", emitT2) <
                (int)sizeof(reportT))
            rT = fcw_read_file(reportT, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES,
                               &rT_len);
        struct vcs_package_build_receipt recT;
        bool recT_ok =
            rT != NULL && vcs_package_build_parse(rT, rT_len, &recT) ==
                              VCS_PACKAGE_BUILD_OK;
        FC_CHECK("testless emit receipt parses", recT_ok);
        FC_CHECK("testless receipt records the honest facts (no test run, "
                 "build-pass only)",
                 recT_ok && !recT.test_ran &&
                     recT.result_class == VCS_PACKAGE_BUILD_RESULT_BUILD_PASS);
        FC_CHECK("testless receipt flags say asan,ubsan=not-run (never ran, "
                 "never claimed clean)",
                 recT_ok &&
                     strstr(recT.flags, "asan,ubsan=not-run") != NULL);
        FC_CHECK("testless receipt stays installable for reproduction",
                 recT_ok && vcs_package_build_installable(&recT));
    }

    /* 12. a real sanitizer finding on the reproduce track: this fixture
     * copy's test reads freed heap — the free is hidden in a second TU so
     * the standard profile's -Werror=use-after-free cannot see it
     * statically, the plain runs pass (exit 0, the page stays mapped), and
     * the ASan run reports and dies by the marker exit code. With the
     * opt-out flag the build still EMITS an installable TEST_PASS receipt
     * (mirroring quick emit's long-standing behavior: the receipt is
     * build+test evidence, not a gate), but the flags string must say
     * "findings" — never "clean". */
    static const char uaf_test[] =
        "/* Deliberate heap-use-after-free: the plain run reads stale but\n"
        " * mapped bytes and exits 0; the ASan run reports and exits by the\n"
        " * marker code. Fixture for the flags-honesty leg only. The free\n"
        " * hides in uaf_helper.c so -Wuse-after-free cannot see it. */\n"
        "#include <stdlib.h>\n"
        "\n"
        "void fixture_uaf_free(void *p);\n"
        "\n"
        "int main(void)\n"
        "{\n"
        "    int *p = (int *)malloc(sizeof(*p));\n"
        "    if (!p)\n"
        "        return 1;\n"
        "    *p = 42;\n"
        "    fixture_uaf_free(p);\n"
        "    volatile int sink = *p;\n"
        "    (void)sink;\n"
        "    return 0;\n"
        "}\n";
    static const char uaf_helper[] =
        "/* Keeps free() out of the test TU's static-analysis reach. */\n"
        "#include <stdlib.h>\n"
        "\n"
        "void fixture_uaf_free(void *p)\n"
        "{\n"
        "    free(p);\n"
        "}\n";
    char pkgF[4096], recipeF_path[4096], emitF[4096], cacheF[4096],
         testF_path[4096], helperF_path[4096];
    bool pathsF_ok =
        snprintf(pkgF, sizeof(pkgF), "%s/pkgF", base) < (int)sizeof(pkgF) &&
        snprintf(recipeF_path, sizeof(recipeF_path), "%s/recipeF.wire",
                 base) < (int)sizeof(recipeF_path) &&
        snprintf(emitF, sizeof(emitF), "%s/emitF", base) <
            (int)sizeof(emitF) &&
        snprintf(cacheF, sizeof(cacheF), "%s/cacheF", base) <
            (int)sizeof(cacheF) &&
        snprintf(testF_path, sizeof(testF_path),
                 "%s/tests/test_tiny_lines.c", pkgF) < (int)sizeof(testF_path) &&
        snprintf(helperF_path, sizeof(helperF_path),
                 "%s/tests/uaf_helper.c", pkgF) < (int)sizeof(helperF_path);
    struct vcs_package_prepare_options optsF;
    memset(&optsF, 0, sizeof(optsF));
    optsF.dir = pkgF;
    memcpy(optsF.publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    optsF.publisher_sequence = 1;
    char prepF_detail[512] = "";
    enum vcs_package_prepare_error prcF = VCS_PACKAGE_PREPARE_ERR_IO;
    bool finding_ready = pathsF_ok &&
        fcw_copy_tree("tests/harness/fixtures/zcode/tiny-lines", pkgF) &&
        fcw_write_file(testF_path, (const uint8_t *)uaf_test,
                       sizeof(uaf_test) - 1u) &&
        fcw_write_file(helperF_path, (const uint8_t *)uaf_helper,
                       sizeof(uaf_helper) - 1u);
    if (finding_ready)
        prcF = vcs_package_prepare(&optsF, &prepF, prepF_detail,
                                   sizeof(prepF_detail));
    char rootF_hex[65] = "", lockF_hex[65] = "";
    if (prcF == VCS_PACKAGE_PREPARE_OK) {
        zcl_hex_encode(prepF.package_root, 32, rootF_hex);
        zcl_hex_encode(prepF.lock_root, 32, lockF_hex);
    }
    finding_ready =
        finding_ready && prcF == VCS_PACKAGE_PREPARE_OK &&
        fcw_write_file(recipeF_path, prepF.recipe_wire,
                       prepF.recipe_wire_len);
    FC_CHECK("use-after-free fixture variant prepared", finding_ready);
    if (!finding_ready && prcF != VCS_PACKAGE_PREPARE_OK)
        printf("    prepare findings: %s\n", prepF_detail);
    if (finding_ready) {
        struct fcw_build_result frun;
        memset(&frun, 0, sizeof(frun));
        fcw_candidate_build(worker, rootF_hex, pkgF, recipeF_path, emitF,
                            lockF_hex, cacheF, true, &frun);
        FC_CHECK("reproduce-shape standard run with an ASan finding still "
                 "emits (evidence, not a gate)", frun.ok);
        if (!frun.ok)
            printf("    findings run: exit %d: %.200s\n", frun.exit_code,
                   frun.first_line);
        printf("    findings run tail: %.200s\n", frun.last_line);
        char reportF[4096];
        if (frun.ok &&
            snprintf(reportF, sizeof(reportF), "%s/build-report", emitF) <
                (int)sizeof(reportF))
            rF = fcw_read_file(reportF, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES,
                               &rF_len);
        struct vcs_package_build_receipt recF;
        bool recF_ok =
            rF != NULL && vcs_package_build_parse(rF, rF_len, &recF) ==
                              VCS_PACKAGE_BUILD_OK;
        FC_CHECK("findings emit receipt parses", recF_ok);
        FC_CHECK("findings receipt flags say asan,ubsan=findings (never "
                 "clean)",
                 recF_ok &&
                     strstr(recF.flags, "asan,ubsan=findings") != NULL);
        FC_CHECK("findings receipt keeps the build+test verdict "
                 "(test-pass, installable) — unchanged emit semantics",
                 recF_ok && recF.test_ran &&
                     recF.result_class == VCS_PACKAGE_BUILD_RESULT_TEST_PASS &&
                     vcs_package_build_installable(&recF));
    }

    /* ── refusal legs: nothing above is trusted, everything re-proves ── */

    char key[65];
    FC_CHECK("a real cache entry was found for the refusal legs",
             fcw_first_entry(cacheA, key));
    if (strlen(key) == 64u) {
        /* R1: a torn pair (sidecar deleted) refuses the WHOLE export. */
        char torn[4096];
        if (snprintf(torn, sizeof(torn), "%s/torn", base) <
            (int)sizeof(torn)) {
            (void)fcw_rm_rf(torn);
            if (fcw_copy_tree(cacheA, torn)) {
                char o[4096], s[4096];
                if (vcs_fastobj_cache_paths(torn, key, o, sizeof(o), s,
                                            sizeof(s)))
                    (void)unlink(s);
                bool refused = !vcs_fastobj_carrier_export(
                    torn, nodeA, rootL, &stRef, err, sizeof(err));
                FC_CHECK("export refuses a torn pair",
                         refused && strstr(err, "torn") != NULL);
                if (!(refused && strstr(err, "torn")))
                    printf("    torn export: %s\n", err);
            } else {
                FC_CHECK("export refuses a torn pair", false);
            }
        }

        /* R2: a sidecar whose object_sha3 lies about its object. */
        char lying[4096];
        if (snprintf(lying, sizeof(lying), "%s/lying", base) <
            (int)sizeof(lying)) {
            (void)fcw_rm_rf(lying);
            if (fcw_copy_tree(cacheA, lying)) {
                char o[4096], s[4096];
                size_t side_len = 0;
                uint8_t *side = NULL;
                if (vcs_fastobj_cache_paths(lying, key, o, sizeof(o), s,
                                            sizeof(s)) &&
                    (side = fcw_read_file(s, VCS_FASTOBJ_SIDECAR_MAX_BYTES,
                                          &side_len)) != NULL) {
                    const char *hit = fcw_find(side, side_len,
                                               "\"object_sha3\":\"");
                    if (hit) {
                        char *hex = (char *)hit +
                                    strlen("\"object_sha3\":\"");
                        hex[0] = hex[0] == '0' ? '1' : '0';
                    }
                    if (hit && fcw_write_file(s, side, side_len)) {
                        bool refused = !vcs_fastobj_carrier_export(
                            lying, nodeA, rootL, &stRef, err, sizeof(err));
                        FC_CHECK("export refuses a lying object_sha3",
                                 refused && strstr(err, "does not hash") !=
                                               NULL);
                        if (!(refused &&
                              strstr(err, "does not hash")))
                            printf("    lying export: %s\n", err);
                    } else {
                        FC_CHECK("export refuses a lying object_sha3",
                                 false);
                    }
                    free(side);
                } else {
                    FC_CHECK("export refuses a lying object_sha3", false);
                }
            } else {
                FC_CHECK("export refuses a lying object_sha3", false);
            }
        }

        /* R3: an entry renamed to a key it does not hash to. */
        char misl[4096];
        if (snprintf(misl, sizeof(misl), "%s/mislabeled", base) <
            (int)sizeof(misl)) {
            (void)fcw_rm_rf(misl);
            if (fcw_copy_tree(cacheA, misl)) {
                char key2[65];
                memcpy(key2, key, 65);
                key2[63] = key2[63] == '0' ? '1' : '0';
                char o1[4096], s1[4096], o2[4096], s2[4096];
                if (vcs_fastobj_cache_paths(misl, key, o1, sizeof(o1), s1,
                                            sizeof(s1)) &&
                    vcs_fastobj_cache_paths(misl, key2, o2, sizeof(o2), s2,
                                            sizeof(s2)) &&
                    rename(o1, o2) == 0 && rename(s1, s2) == 0) {
                    bool refused = !vcs_fastobj_carrier_export(
                        misl, nodeA, rootL, &stRef, err, sizeof(err));
                    FC_CHECK("export refuses an entry filed under a "
                             "wrong key",
                             refused && strstr(err, "filed under") != NULL);
                    if (!(refused && strstr(err, "filed under")))
                        printf("    mislabeled export: %s\n", err);
                } else {
                    FC_CHECK(
                        "export refuses an entry filed under a wrong key",
                        false);
                }
            } else {
                FC_CHECK("export refuses an entry filed under a wrong key",
                         false);
            }
        }

        /* R4: a hand-built carrier whose sidecar is filed under a key it
         * does not hash to — ADMIT must refuse at the destination. */
        {
            char o[4096], s[4096];
            size_t obj_len = 0, side_len = 0;
            uint8_t *obj = NULL, *side = NULL;
            if (vcs_fastobj_cache_paths(cacheA, key, o, sizeof(o), s,
                                        sizeof(s)) &&
                (obj = fcw_read_file(
                     o, VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES, &obj_len)) !=
                    NULL &&
                (side = fcw_read_file(
                     s, VCS_FASTOBJ_SIDECAR_MAX_BYTES, &side_len)) !=
                    NULL) {
                char key2[65];
                memcpy(key2, key, 65);
                key2[63] = key2[63] == '0' ? '1' : '0';
                char cobj[4096], cside[4096];
                struct vcs_package_manifest manifest;
                vcs_package_manifest_init(&manifest);
                uint8_t *wire = NULL;
                size_t wire_len = 0;
                bool built =
                    snprintf(cobj, sizeof(cobj), "%s/%s.o",
                             VCS_FASTOBJ_CARRIER_DIR, key2) <
                        (int)sizeof(cobj) &&
                    snprintf(cside, sizeof(cside), "%s/%s.json",
                             VCS_FASTOBJ_CARRIER_DIR, key2) <
                        (int)sizeof(cside) &&
                    vcs_package_content_add_file(&manifest, cobj,
                                                 VCS_PACKAGE_MODE_FILE, obj,
                                                 obj_len) &&
                    vcs_package_content_add_file(&manifest, cside,
                                                 VCS_PACKAGE_MODE_FILE, side,
                                                 side_len) &&
                    vcs_package_manifest_serialize(&manifest, &wire,
                                                   &wire_len) &&
                    vcs_package_manifest_root(&manifest, rootL);
                storeR = vcs_package_store_open(
                    dirR, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
                uint8_t stored[32] = {0};
                bool stored_ok =
                    built && storeR != NULL &&
                    vcs_package_store_put_manifest(storeR, wire, wire_len,
                                                   stored) ==
                        VCS_PACKAGE_STORE_OK &&
                    memcmp(stored, rootL, 32) == 0 &&
                    vcs_package_content_put_file(storeR, rootL, cobj, obj,
                                                 obj_len) ==
                        VCS_PACKAGE_STORE_OK &&
                    vcs_package_content_put_file(storeR, rootL, cside, side,
                                                 side_len) ==
                        VCS_PACKAGE_STORE_OK;
                FC_CHECK("lying carrier hand-built and stored", stored_ok);
                if (stored_ok) {
                    char admit_dir[4096];
                    if (snprintf(admit_dir, sizeof(admit_dir), "%s/admitX",
                                 base) < (int)sizeof(admit_dir)) {
                        bool refused =
                            !vcs_fastobj_carrier_admit(admit_dir, storeR,
                                                       rootL, &stRef, err,
                                                       sizeof(err));
                        FC_CHECK("admit refuses a carrier whose sidecar "
                                 "lies about its key",
                                 refused &&
                                     strstr(err, "filed under") != NULL);
                        if (!(refused && strstr(err, "filed under")))
                            printf("    lying admit: %s\n", err);
                    }
                    /* The public-shape gate runs the same proof the admit
                     * above just refused: no shape, no announce, no serve. */
                    struct vcs_package_public_verdict lie_v;
                    enum vcs_package_public_shape pub_l =
                        vcs_package_public_shape_classify(storeR, rootL,
                                                          &lie_v);
                    FC_CHECK("the public-shape gate refuses the lying "
                             "carrier",
                             pub_l == VCS_PACKAGE_PUBLIC_REFUSED &&
                                 lie_v.rule != NULL &&
                                 strncmp(lie_v.rule, "fastobj-carrier",
                                         15) == 0);
                }
                free(wire);
                vcs_package_manifest_free(&manifest);
            } else {
                FC_CHECK("lying carrier hand-built and stored", false);
            }
            free(obj);
            free(side);
        }
    }

done:
    free(r1);
    free(r2);
    free(rT);
    free(rF);
    vcs_package_prepared_free(&prep);
    vcs_package_prepared_free(&prepT);
    vcs_package_prepared_free(&prepF);
    if (nodeA)
        vcs_package_store_close(nodeA);
    if (nodeB)
        vcs_package_store_close(nodeB);
    if (nodeC)
        vcs_package_store_close(nodeC);
    if (nodeD)
        vcs_package_store_close(nodeD);
    if (storeR)
        vcs_package_store_close(storeR);
    if (failures == 0) {
        (void)fcw_rm_rf(base);
    } else {
        printf("fastobj_carrier: scratch kept for inspection: %s\n", base);
    }
    printf("fastobj_carrier: %s (%d failure%s)\n",
           failures ? "FAIL" : "PASS", failures, failures == 1 ? "" : "s");
    return failures;
}

#else /* _WIN32 */

/* Every candidate build here runs the confined package verifier with
 * --require-full-isolation, which refuses off Linux (no Landlock/seccomp;
 * the Windows sandbox is unqualified). The fork+pipe drain plumbing has no
 * Windows analogue either, so no case in this group can run. */
static int test_fastobj_carrier_platform_arm(void)
{
    printf("test_fastobj_carrier: SKIP (Windows): confined package builds "
           "require Linux full isolation\n");
    return 0;
}

#endif /* !_WIN32 */

int test_fastobj_carrier(void)
{
    return test_fastobj_carrier_platform_arm();
}
