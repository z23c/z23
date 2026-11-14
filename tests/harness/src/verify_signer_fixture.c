/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: The verify_signer dress-rehearsal world: the real worker's
 *          qualify output, a fixture launcher that writes root-style launch
 *          records, fresh verifier state trees, and the receiver's own cold
 *          compile and store lookup. See test/verify_signer_fixture.h. */
#if defined(__linux__)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "test/verify_signer_fixture.h"

#include "test/test_core.h"
#include "test/verify_contract_fixture.h"

#include "base/hex.h"
#include "crypto/ed25519.h"
#include "sha3/sha3.h"
#include "verify/fixed_result_source.h"

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define VSG_PROFILE "tools/verify/fixed_result_fast.args"
#define VSG_TARGET "build/test-obj/epochs/" \
    "0033ccae6a292700d2b299aec57e346aa7f719bac2798a620d2ba9e155ebca5e" \
    "/platform/modules/base/src/result.o"
#define VSG_SCRATCH "/work/result.Qz7x2A"
#define VSG_PASS_ID "0123456789abcdef0123456789abcdef"
#define VSG_FAIL_ID "fedcba9876543210fedcba9876543210"
#define VSG_ARGS (ZCL_FR_PROFILE_ARGC + 16u)

int zcl_test_fixed_result_worker_main(int argc, char **argv);

static const char *const k_vsg_env[] = {
    "LC_ALL=C", "TZ=UTC", "TMPDIR=/tmp", "PATH=/usr/bin:/bin", NULL
};

/* ── small file helpers ───────────────────────────────────────────────── */

bool vsg_path(char out[PATH_MAX], const char *a, const char *b)
{
    int n = snprintf(out, PATH_MAX, "%s/%s", a, b);
    return n > 0 && n < PATH_MAX;
}

static bool vsg_write(const char *path, const void *bytes, size_t len,
                      unsigned mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                  0600);
    if (fd < 0) return false;
    const uint8_t *p = bytes;
    size_t at = 0;
    while (at < len) {
        ssize_t n = write(fd, p + at, len - at);
        if (n <= 0) break;
        at += (size_t)n;
    }
    bool ok = at == len && fchmod(fd, (mode_t)mode) == 0;
    return close(fd) == 0 && ok;
}

bool vsg_file_replace(const char *dir, const char *name, const void *bytes,
                      size_t len, unsigned mode)
{
    char path[PATH_MAX];
    return vsg_path(path, dir, name) &&
           (unlink(path) == 0 || errno == ENOENT) &&
           vsg_write(path, bytes, len, mode);
}

static bool vsg_read(const char *path, struct vsg_bytes *out)
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    bool ok = fseek(f, 0, SEEK_END) == 0;
    long size = ok ? ftell(f) : -1;
    ok = ok && size >= 0 && fseek(f, 0, SEEK_SET) == 0;
    out->p = ok ? malloc((size_t)size + 1u) : NULL;
    out->n = (size_t)(size < 0 ? 0 : size);
    ok = ok && out->p && fread(out->p, 1, out->n, f) == out->n;
    ok = fclose(f) == 0 && ok;
    return ok;
}

static bool vsg_mkdir(const char *path, unsigned mode)
{
    return mkdir(path, 0700) == 0 && chmod(path, (mode_t)mode) == 0;
}

static bool vsg_subdir(char out[PATH_MAX], const char *parent,
                       const char *name, unsigned mode)
{
    return vsg_path(out, parent, name) && vsg_mkdir(out, mode);
}

/* Fresh private files preserve the worker's pinned bytes without requiring
 * the caller's checkout to have production source-image permissions. */
static bool vsg_input_write(const char *root, const char *rel,
                            const void *bytes, size_t len)
{
    char path[PATH_MAX];
    if (!vsg_path(path, root, rel)) return false;
    char *part = path + strlen(root) + 1u;
    while ((part = strchr(part, '/')) != NULL) {
        *part = '\0';
        if (mkdir(path, 0700) != 0 && errno != EEXIST) return false;
        *part++ = '/';
    }
    return vsg_write(path, bytes, len, 0444u);
}

static bool vsg_inputs(struct vsg_world *w)
{
    char source[PATH_MAX];
    if (!vsg_subdir(source, w->root, "source", 0700u) ||
        !realpath(source, w->cwd)) return false;
    for (size_t i = 0; i < ZCL_FR_SOURCE_CHAIN_COUNT; i++) {
        struct vsg_bytes bytes = {0};
        const char *rel = zcl_fr_source_chain[i];
        bool ok = vsg_read(rel, &bytes) &&
                  vsg_input_write(w->cwd, rel, bytes.p, bytes.n);
        vsg_bytes_free(&bytes);
        if (!ok) return false;
    }
    return vsg_input_write(w->cwd, VSG_PROFILE, w->profile.p, w->profile.n);
}

void vsg_bytes_free(struct vsg_bytes *b)
{
    free(b->p);
    b->p = NULL;
    b->n = 0;
}

void vsg_hex(const uint8_t *bytes, size_t len, char out[65])
{
    uint8_t hash[32];
    zcl_sha3_256(bytes, len, hash);
    zcl_hex_encode(hash, sizeof(hash), out);
}

/* ── trust files ──────────────────────────────────────────────────────── */

bool vsg_etc_write(const struct vsg_state *s, const char *name,
                   const void *bytes, size_t len)
{
    bool pub = strstr(name, ".pub") != NULL;
    return vsg_file_replace(s->etc, name, bytes, len, pub ? 0644u : 0444u);
}

bool vsg_etc_pins(const struct vsg_state *s,
                  const struct zcl_fixed_result_v2_roots *pins)
{
    uint8_t bytes[2048];
    size_t len = 0;
    return zcl_fr_pins_encode(pins, bytes, sizeof(bytes), &len, NULL) &&
           vsg_etc_write(s, ZCL_FRT_PINS, bytes, len);
}

static bool vsg_pub_file(const char *dir, const char *name,
                         const uint8_t pub[32], unsigned mode)
{
    char hex[66];
    zcl_hex_encode(pub, 32u, hex);
    hex[64] = '\n';
    return vsg_file_replace(dir, name, hex, 65u, mode);
}

bool vsg_etc_pubkey(const struct vsg_state *s, const char *name,
                    const uint8_t pub[32])
{
    return vsg_pub_file(s->etc, name, pub, 0644u);
}

/* The site's etc as root installs it, with this test's UID in the policy
 * where production names 60092 and 0. */
static bool vsg_site_etc(const struct vsg_world *w, const struct vsg_state *s)
{
    char policy[96];
    unsigned me = (unsigned)geteuid();
    int n = snprintf(policy, sizeof(policy),
                     "z23verify.store.v1\nsigner_uid=%u\npublisher_uid=%u\n",
                     me, me);
    return n > 0 && (size_t)n < sizeof(policy) &&
           vsg_etc_write(s, ZCL_FRT_POLICY, policy, (size_t)n) &&
           vsg_etc_pins(s, &w->pins) &&
           vsg_etc_write(s, ZCL_FRT_PROFILE, w->profile.p, w->profile.n) &&
           vsg_etc_pubkey(s, ZCL_FRT_VERIFIER_PUB, w->pub) &&
           vsg_etc_pubkey(s, ZCL_FRT_BOX_PUB, w->box_pub);
}

static bool vsg_trust_files(struct vsg_world *w)
{
    uint8_t secret[32], box_secret[32];
    memset(w->seed, 0x5a, sizeof(w->seed));
    ed25519_keypair(w->pub, secret, w->seed);
    memset(w->box_seed, 0x6b, sizeof(w->box_seed));
    ed25519_keypair(w->box_pub, box_secret, w->box_seed);
    w->box = (struct zcl_verify_attest_box_key){.known = true,
                                                .present = true};
    memcpy(w->box.pubkey, w->box_pub, 32u);
    test_vc_pins(&w->pins);
    char key_pub[PATH_MAX];
    return vsg_read(VSG_PROFILE, &w->profile) &&
           test_vs_key_root_make(w->key_root) &&
           vsg_pub_file(w->key_root, "verifier.pub", w->pub, 0644u) &&
           vsg_path(key_pub, w->key_root, "verifier.pub") &&
           setenv("ZCL_TEST_VERIFY_ATTEST_PUBKEY", key_pub, 1) == 0;
}

/* ── the real worker ──────────────────────────────────────────────────── */

static bool vsg_wait_ok(pid_t pid)
{
    int status = 0;
    pid_t done;
    do { done = waitpid(pid, &status, 0); } while (done < 0 && errno == EINTR);
    return done == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static void vsg_redirect(const char *dir, const char *out_name,
                         const char *err_name)
{
    char out[PATH_MAX], err[PATH_MAX];
    int o = vsg_path(out, dir, out_name) ? open(out, O_WRONLY | O_CREAT |
                                                    O_TRUNC, 0600) : -1;
    int e = vsg_path(err, dir, err_name) ? open(err, O_WRONLY | O_CREAT |
                                                    O_TRUNC, 0600) : -1;
    if (o < 0 || e < 0 || dup2(o, STDOUT_FILENO) < 0 ||
        dup2(e, STDERR_FILENO) < 0)
        _exit(125);
}

/* The worker's refusal, and for a drifted pin the exact re-pin steps: an
 * unrelated edit to result.c must point here, not look like a signer bug. */
static void vsg_worker_explain(const struct vsg_world *w)
{
    char path[PATH_MAX];
    struct vsg_bytes err = {0};
    bool read = vsg_path(path, w->build, "worker.err") && vsg_read(path, &err);
    printf("verify signer: worker qualify failed: %.*s\n",
           read ? (int)err.n : 0, read ? (const char *)err.p : "");
    if (read && memmem(err.p, err.n, "pinned_input_", 13u))
        printf(
            "verify signer: the worker pins the exact bytes of "
            "platform/modules/base/src/result.c, base/include/base/result.h "
            "and base/include/base/format_attribute.h, and one changed.\n"
            "  Re-pin: 1. for each path in pinned_inputs[] in "
            "tools/verify/fixed_result_worker.c run "
            "`openssl dgst -sha3-256 <path>` and replace its hex;\n"
            "  2. rerun `make -j8 t-fast-exact "
            "ONLY=verify_signer,verify_contract` (the evidence line's "
            "object_sha3 changes with the source);\n"
            "  3. the worker binary changes, so an installed verifier needs "
            "root to rebuild the source image and re-pin worker_sha3, "
            "source_image and source_content "
            "(docs/work/verifier-install-packet.md sections 2, 5 and 7).\n");
    vsg_bytes_free(&err);
}

/* `worker qualify <cwd> <target> <outdir>` in a forked child: the same
 * profile, pinned inputs, -E then -c, and depfile equality it runs in the
 * jail, with no root peer and attest_eligible=0. */
static bool vsg_worker(struct vsg_world *w)
{
    char outdir[PATH_MAX], path[PATH_MAX];
    if (!vsg_subdir(outdir, w->build, "worker", 0700u)) return false;
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        vsg_redirect(w->build, "worker.out", "worker.err");
        if (chdir(w->cwd) != 0) _exit(125);
        char *argv[] = {"fixed_result_worker", "qualify", w->cwd, w->target,
                        outdir, NULL};
        int rc = zcl_test_fixed_result_worker_main(5, argv);
        fflush(NULL);
        _exit(rc);
    }
    if (!vsg_wait_ok(pid)) {
        vsg_worker_explain(w);
        return false;
    }
    return vsg_path(path, outdir, "result.o") && vsg_read(path, &w->object) &&
           vsg_path(path, outdir, "deps.d") && vsg_read(path, &w->deps) &&
           vsg_path(path, outdir, "stderr.bin") && vsg_read(path, &w->err) &&
           vsg_path(path, outdir, "result.i") && vsg_read(path, &w->pp);
}

/* ── the fixture launcher ─────────────────────────────────────────────── */

struct vsg_argv {
    char *lines;
    char cwd_line[8192];
    char dep[PATH_MAX];
    char out[PATH_MAX];
    const char *argv[VSG_ARGS];
    size_t argc;
};

/* The profile's lines with its one @CWD@ spelled as `cwd`. */
static bool vsg_profile_argv(const struct vsg_world *w, const char *cwd,
                             struct vsg_argv *a)
{
    memset(a, 0, sizeof(*a));
    a->lines = malloc(w->profile.n + 1u);
    if (!a->lines) return false;
    memcpy(a->lines, w->profile.p, w->profile.n);
    a->lines[w->profile.n] = '\0';
    for (char *line = a->lines, *nl; (nl = strchr(line, '\n')) != NULL;
         line = nl + 1) {
        if (a->argc >= ZCL_FR_PROFILE_ARGC) return false;
        *nl = '\0';
        const char *tag = strstr(line, "@CWD@");
        if (tag) {
            (void)snprintf(a->cwd_line, sizeof(a->cwd_line), "%.*s%s%s",
                           (int)(tag - line), line, cwd, tag + 5);
            a->argv[a->argc++] = a->cwd_line;
        } else {
            a->argv[a->argc++] = line;
        }
    }
    return a->argc == ZCL_FR_PROFILE_ARGC;
}

/* The worker's -c tail, or its checker -E tail, with `dir` holding its
 * outputs (a /work scratch spelling or a /proc/self/fd directory) and `dep`
 * the -c depfile's leaf (deps.d in the jail, result.d for ZCC). */
static void vsg_tail(struct vsg_argv *a, const char *dir, const char *target,
                     bool preprocess, const char *dep)
{
    (void)snprintf(a->dep, sizeof(a->dep), "%s/%s", dir,
                   preprocess ? "preprocess.d" : dep);
    (void)snprintf(a->out, sizeof(a->out), "%s/%s", dir,
                   preprocess ? "result.i" : "result.o");
    const char *tail[] = {"-MMD", "-MP", "-MF", a->dep, "-MT", target};
    for (size_t i = 0; i < sizeof(tail) / sizeof(tail[0]); i++)
        a->argv[a->argc++] = tail[i];
    if (preprocess) a->argv[a->argc++] = "-fno-working-directory";
    a->argv[a->argc++] = preprocess ? "-E" : "-c";
    a->argv[a->argc++] = "-o";
    a->argv[a->argc++] = a->out;
    a->argv[a->argc++] = ZCL_FR_SOURCE;
    a->argv[a->argc] = NULL;
}

static bool vsg_exec_hash(const struct vsg_world *w, bool preprocess,
                          uint8_t out[32])
{
    struct vsg_argv a;
    bool ok = vsg_profile_argv(w, ZCL_FR_CWD, &a);
    if (ok) {
        vsg_tail(&a, VSG_SCRATCH, w->target, preprocess, "deps.d");
        ok = zcl_fr_exec_argv_sha3(a.argv, a.argc, out);
    }
    free(a.lines);
    return ok;
}

static void vsg_digest(struct zcl_fr_artifact_digest *d, const void *p,
                       size_t n)
{
    d->size = n;
    zcl_sha3_256(p, n, d->sha3);
}

/* Fields 1-37 as the root launcher would observe them. */
static bool vsg_receipt_head(const struct vsg_world *w, const char *id,
                             struct zcl_fr_receipt *r)
{
    char tool[65];
    memset(r, 0, sizeof(*r));
    memcpy(r->launch_id, id, ZCL_FR_ID_LEN);
    memcpy(r->request_nonce, "00112233445566778899aabbccddeeff", ZCL_FR_ID_LEN);
    memcpy(r->target, w->target, ZCL_FR_TARGET_LEN);
    zcl_hex_encode(w->pins.tool_image, 32u, tool);
    (void)snprintf(r->toolchain_id, sizeof(r->toolchain_id), "%s%s",
                   ZCL_FR_TOOLCHAIN_PREFIX, tool);
    r->pins = w->pins;
    memcpy(r->scratch, VSG_SCRATCH, ZCL_FR_SCRATCH_LEN);
    r->mount_namespace_dev = 4u;
    r->mount_namespace_ino = 4026531841u;
    return vsg_exec_hash(w, false, r->compile_argv_sha3) &&
           vsg_exec_hash(w, true, r->preprocess_argv_sha3);
}

static bool vsg_receipts(struct vsg_world *w)
{
    struct zcl_fr_receipt r;
    if (!vsg_receipt_head(w, VSG_PASS_ID, &r)) return false;
    vsg_digest(&r.artifacts[0], w->object.p, w->object.n);
    vsg_digest(&r.artifacts[1], w->deps.p, w->deps.n);
    vsg_digest(&r.artifacts[2], w->err.p, w->err.n);
    vsg_digest(&r.artifacts[3], w->pp.p, w->pp.n);
    memcpy(w->pass.id, VSG_PASS_ID, sizeof(w->pass.id));
    if (!zcl_fr_receipt_encode(&r, w->pass.bytes, sizeof(w->pass.bytes),
                               &w->pass.len, NULL))
        return false;
    struct zcl_fr_failure f = {.compile_exit = 1u};
    if (!vsg_receipt_head(w, VSG_FAIL_ID, &f.launch)) return false;
    vsg_digest(&f.launch.artifacts[2], VSG_FAIL_STDERR,
               sizeof(VSG_FAIL_STDERR) - 1u);
    vsg_digest(&f.launch.artifacts[3], w->pp.p, w->pp.n);
    memcpy(w->fail.id, VSG_FAIL_ID, sizeof(w->fail.id));
    w->fail.failure = true;
    return zcl_fr_failure_encode(&f, w->fail.bytes, sizeof(w->fail.bytes),
                                 &w->fail.len, NULL);
}

/* launches/<id>/: the artifacts mode 0400, launch.bin 0444 written last. */
static bool vsg_launch_dir(const struct vsg_world *w, const char *launches,
                           const struct vsg_launch *l, char out[PATH_MAX])
{
    if (!vsg_subdir(out, launches, l->id, 0700u)) return false;
    bool ok = l->failure
        ? vsg_file_replace(out, "stderr.bin", VSG_FAIL_STDERR,
                           sizeof(VSG_FAIL_STDERR) - 1u, 0400u)
        : vsg_file_replace(out, "object.o", w->object.p, w->object.n, 0400u) &&
          vsg_file_replace(out, "deps.d", w->deps.p, w->deps.n, 0400u) &&
          vsg_file_replace(out, "stderr.bin", w->err.p, w->err.n, 0400u);
    return ok &&
           vsg_file_replace(out, "preprocessed.i", w->pp.p, w->pp.n, 0400u) &&
           vsg_file_replace(out, "launch.bin", l->bytes, l->len, 0444u);
}

/* anchor/etc/z23verify and anchor/var/lib/z23verify, the site layout
 * production walks from "/". */
static bool vsg_site_dirs(struct vsg_world *w, struct vsg_state *s)
{
    char name[32], etc[PATH_MAX], var[PATH_MAX], lib[PATH_MAX];
    (void)snprintf(name, sizeof(name), "site-%u", w->states++);
    return vsg_subdir(s->anchor, w->root, name, 0755u) &&
           vsg_subdir(etc, s->anchor, "etc", 0755u) &&
           vsg_subdir(s->etc, etc, "z23verify", 0755u) &&
           vsg_subdir(var, s->anchor, "var", 0755u) &&
           vsg_subdir(lib, var, "lib", 0755u) &&
           vsg_subdir(s->dir, lib, "z23verify", 0755u);
}

bool vsg_state_make(struct vsg_world *w, struct vsg_state *s)
{
    char dir[PATH_MAX], launches[PATH_MAX];
    memset(s, 0, sizeof(*s));
    return vsg_site_dirs(w, s) && vsg_site_etc(w, s) &&
           vsg_subdir(s->staging, s->dir, "staging", 0700u) &&
           vsg_subdir(s->key_dir, s->dir, "key", 0700u) &&
           vsg_file_replace(s->key_dir, ZCL_FRS_KEY_NAME, w->seed, 32u,
                            0400u) &&
           vsg_subdir(dir, s->dir, "store", 0755u) &&
           vsg_subdir(dir, s->dir, "locks", 0755u) &&
           vsg_path(s->lock, dir, "fixed_result.lock") &&
           vsg_write(s->lock, "", 0u, 0644u) &&
           vsg_subdir(dir, s->dir, "publish-tmp", 0700u) &&
           vsg_subdir(dir, s->dir, "conflicts", 0700u) &&
           vsg_subdir(launches, s->dir, "launches", 0755u) &&
           vsg_launch_dir(w, launches, &w->pass, s->pass_launch) &&
           vsg_launch_dir(w, launches, &w->fail, s->fail_launch);
}

bool vsg_world_make(struct vsg_world *w)
{
    char made[PATH_MAX];
    memset(w, 0, sizeof(*w));
    memcpy(w->target, VSG_TARGET, sizeof(VSG_TARGET));
    if (!test_mkdtemp(made, sizeof(made), "z23-verify-signer") ||
        !realpath(made, w->root))
        return false;
    return vsg_subdir(w->build, w->root, "build", 0700u) &&
           vsg_trust_files(w) && vsg_inputs(w) &&
           vsg_worker(w) && vsg_receipts(w);
}

static int vsg_rm_entry(const char *path, const struct stat *st, int type,
                        struct FTW *walk)
{
    (void)st; (void)type; (void)walk;
    return remove(path);
}

void vsg_world_free(struct vsg_world *w)
{
    (void)unsetenv("ZCL_TEST_VERIFY_ATTEST_PUBKEY");
    if (w->root[0]) (void)nftw(w->root, vsg_rm_entry, 16, FTW_DEPTH | FTW_PHYS);
    if (w->key_root[0])
        (void)nftw(w->key_root, vsg_rm_entry, 4, FTW_DEPTH | FTW_PHYS);
    vsg_bytes_free(&w->profile);
    vsg_bytes_free(&w->object);
    vsg_bytes_free(&w->deps);
    vsg_bytes_free(&w->err);
    vsg_bytes_free(&w->pp);
}

/* ── signer and publisher fixtures ────────────────────────────────────── */

static struct zcl_frt_fixture vsg_trust(const struct vsg_state *s)
{
    uint32_t me = (uint32_t)geteuid();
    return (struct zcl_frt_fixture){s->etc, me, me, me, me};
}

struct zcl_frs_fixture vsg_signer(const struct vsg_state *s)
{
    return (struct zcl_frs_fixture){vsg_trust(s), s->key_dir, s->staging,
                                    true};
}

struct zcl_frp_fixture vsg_publisher(const struct vsg_state *s)
{
    return (struct zcl_frp_fixture){vsg_trust(s), s->staging, s->dir, 2000u,
                                    true};
}

void vsg_seal(const struct zcl_frs_fixture *fx, const char *launch_dir,
              struct zcl_frs_result *out)
{
    int fds[ZCL_FRS_INPUTS];
    int dir = open(launch_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    const char *why = dir >= 0 ? zcl_frs_inputs_open(dir, fds)
                               : ZCL_FRS_WHY_INPUTS;
    if (dir >= 0) (void)close(dir);
    if (why) {
        memset(out, 0, sizeof(*out));
        out->reason = why;
        return;
    }
    zcl_frs_seal_fixture(fx, fds, out);
    zcl_frs_inputs_close(fds);
}

/* ── the receiver ─────────────────────────────────────────────────────── */

/* Direct-source GCC in a child that keeps `dirfd` open under the same
 * number, as ZCC reaches its private output directory. */
static bool vsg_cc(const struct vsg_argv *a, const char *cwd,
                    int dirfd, const char *err)
{
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        if (chdir(cwd) != 0) _exit(125);
        int e = openat(dirfd, err, O_WRONLY | O_CREAT | O_EXCL, 0600);
        int nul = open("/dev/null", O_RDWR);
        if (e < 0 || nul < 0 || fcntl(dirfd, F_SETFD, 0) != 0 ||
            dup2(nul, STDIN_FILENO) < 0 || dup2(nul, STDOUT_FILENO) < 0 ||
            dup2(e, STDERR_FILENO) < 0)
            _exit(125);
        execve("/usr/bin/cc", (char *const *)a->argv, (char *const *)k_vsg_env);
        _exit(127);
    }
    return vsg_wait_ok(pid);
}

static bool vsg_cold(const struct vsg_world *w, int dirfd, bool preprocess,
                     struct vsg_argv *a)
{
    char dir[64];
    (void)snprintf(dir, sizeof(dir), "/proc/self/fd/%d", dirfd);
    if (!vsg_profile_argv(w, w->cwd, a)) return false;
    vsg_tail(a, dir, w->target, preprocess, "result.d");
    return vsg_cc(a, w->cwd, dirfd,
                  preprocess ? "preprocess.err" : "stderr.bin");
}

bool vsg_receive(struct vsg_world *w, const struct vsg_state *s,
                 const char *tag, bool allow_same_uid,
                 struct zcl_verify_store_result *out,
                 struct vsg_bytes *cold_object)
{
    char outdir[PATH_MAX], path[PATH_MAX];
    struct vsg_argv e = {0}, c = {0};
    struct vsg_bytes pp = {0};
    struct zcl_fixed_result_v2_expected *x = calloc(1u, sizeof(*x));
    int dirfd = -1;
    bool ok = x && vsg_subdir(outdir, w->build, tag, 0700u) &&
              (dirfd = open(outdir, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) >= 0 &&
              vsg_cold(w, dirfd, true, &e) && vsg_cold(w, dirfd, false, &c) &&
              vsg_path(path, outdir, "result.i") && vsg_read(path, &pp) &&
              vsg_path(path, outdir, "result.o") && vsg_read(path, cold_object) &&
              pp.n == w->pp.n && memcmp(pp.p, w->pp.p, pp.n) == 0;
    if (ok) {
        uint8_t pp_sha3[32];
        zcl_sha3_256(pp.p, pp.n, pp_sha3);
        ok = zcl_fixed_result_expected_v2(
            &w->pins, w->pins.source_content, pp_sha3, w->target, w->profile.p,
            w->profile.n, w->cwd, c.argv, c.argc, k_vsg_env, 4u, dirfd, x, NULL);
    }
    if (ok)
        zcl_verify_store_lookup_site_fixture(s->anchor, allow_same_uid,
                                             &x->expected, &w->box, out);
    if (dirfd >= 0) (void)close(dirfd);
    free(e.lines);
    free(c.lines);
    free(x);
    vsg_bytes_free(&pp);
    return ok;
}
#else
typedef int zcl_test_verify_signer_fixture_linux_only;
#endif
