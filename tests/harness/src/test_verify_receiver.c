/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * The fixed result.c receiver end to end, on ZCL_TESTING trust roots and a
 * fixture store only: a real verifier-shaped compile in one directory, the
 * receiver's own -E and admission in another, the real zcc epoch publisher
 * serving (or refusing) the admitted bytes, a launch counter on the
 * compiler, and a link of the served object. Never the production store. */
#define _XOPEN_SOURCE 700
#include "test/test_core.h"

#if !defined(__linux__)
int test_verify_receiver(void) { return 0; }
#else
#include "base/hex.h"
#include "crypto/ed25519.h"
#include "sha3/sha3.h"
#include "verify_attest.h"
#include "verify_receiver.h"
#include "verify_receiver_internal.h"
#include "verify_store.h"
#include "platform/temp_directory.h"
#include "verify/fixed_result_contract.h"
#include "verify/fixed_result_source.h"
#include "test/verify_contract_fixture.h"

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define VRT_KEY_ENV "ZCL_TEST_VERIFY_ATTEST_PUBKEY"
#define VRT_SOURCE ZCL_FR_SOURCE
#define VRT_HEX_A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

static const uint8_t vrt_seed[32] = {0x51};

/* Build in place and never copy. */
struct vrt_fx {
    char cwd[PATH_MAX], root[PATH_MAX], gen[PATH_MAX], donor[PATH_MAX];
    char probe[PATH_MAX], vstore[PATH_MAX], store[PATH_MAX];
    char anchor[PATH_MAX], etc[PATH_MAX];
    char key_root[PATH_MAX], pubfile[PATH_MAX], work[PATH_MAX];
    char bin[PATH_MAX], counter[PATH_MAX], zcc[PATH_MAX], profile[PATH_MAX];
    char phases[PATH_MAX], key_dir[PATH_MAX], pass_name[65], zstore[PATH_MAX];
    char donor_target[ZCL_FR_TARGET_LEN + 1u];
    char **inputs;
    size_t input_count;
    struct vr_bytes obj, dep, err;
    uint8_t pp[32];
    size_t pp_len;
    struct zcl_fixed_result_v2_roots pins;
    struct zcl_fixed_result_v2_expected signer;
    uint8_t receipt[TEST_VC_RECEIPT_CAP];
    size_t receipt_len;
    struct zcl_verify_attest_box_key box;
    struct zcl_verify_receiver_fixture fixture;
};

/* ── small file helpers ────────────────────────────────────────────────── */

static bool vrt_path(char out[PATH_MAX], const char *a, const char *b)
{
    int n = snprintf(out, PATH_MAX, "%s/%s", a, b);
    return n > 0 && n < PATH_MAX;
}

static bool vrt_mkdirs(const char *path)
{
    char p[PATH_MAX];
    if (snprintf(p, sizeof(p), "%s", path) >= (int)sizeof(p)) return false;
    for (char *s = p + 1; *s; s++) {
        if (*s != '/') continue;
        *s = 0;
        if (mkdir(p, 0755) != 0 && errno != EEXIST) return false;
        *s = '/';
    }
    return mkdir(p, 0755) == 0 || errno == EEXIST;
}

static bool vrt_write(const char *path, const void *bytes, size_t len,
                      mode_t mode)
{
    (void)unlink(path);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    if (fd < 0) return false;
    const uint8_t *p = bytes;
    size_t at = 0;
    while (at < len) {
        ssize_t n = write(fd, p + at, len - at);
        if (n <= 0) { (void)close(fd); return false; }
        at += (size_t)n;
    }
    bool ok = fchmod(fd, mode) == 0;
    return close(fd) == 0 && ok;
}

static bool vrt_read(const char *path, struct vr_bytes *out)
{
    free(out->p);
    out->p = NULL;
    out->n = 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (fd < 0) return false;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
              st.st_size < 64 * 1024 * 1024;
    out->p = ok ? malloc((size_t)st.st_size + 1u) : NULL;
    while (out->p && out->n < (size_t)st.st_size) {
        ssize_t n = read(fd, out->p + out->n, (size_t)st.st_size - out->n);
        if (n <= 0) break;
        out->n += (size_t)n;
    }
    ok = out->p && out->n == (size_t)st.st_size;
    (void)close(fd);
    return ok;
}

static bool vrt_copy(const char *from, const char *to)
{
    struct vr_bytes b = {0};
    char parent[PATH_MAX];
    if (snprintf(parent, sizeof(parent), "%s", to) >= (int)sizeof(parent))
        return false;
    char *slash = strrchr(parent, '/');
    if (!slash) return false;
    *slash = 0;
    bool ok = vrt_mkdirs(parent) && vrt_read(from, &b) &&
              vrt_write(to, b.p, b.n, 0644);
    free(b.p);
    return ok;
}

static bool vrt_same_file(const char *a, const char *b)
{
    struct vr_bytes x = {0}, y = {0};
    bool same = vrt_read(a, &x) && vrt_read(b, &y) && x.n == y.n &&
                memcmp(x.p, y.p, x.n) == 0;
    free(x.p);
    free(y.p);
    return same;
}

static int vrt_rm(const char *path, const struct stat *st, int type,
                  struct FTW *walk)
{
    (void)st; (void)type; (void)walk;
    return remove(path);
}

/* ── processes ─────────────────────────────────────────────────────────── */

static int vrt_run(const char *cwd, char *const argv[], char *const envp[],
                   const char *err_path)
{
    pid_t pid = fork();
    if (pid == 0) {
        int err = open(err_path ? err_path : "/dev/null",
                       O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (err < 0 || null_fd < 0 || chdir(cwd) != 0 ||
            dup2(null_fd, 0) < 0 || dup2(null_fd, 1) < 0 || dup2(err, 2) < 0)
            _exit(127);
        execve(argv[0], argv, envp);
        _exit(127);
    }
    int status = 0;
    if (pid < 0) return -1;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static char *vrt_fixed_env[] = {
    "LC_ALL=C", "TZ=UTC", "TMPDIR=/tmp", "PATH=/usr/bin:/bin", NULL
};

/* The verifier-shaped compile: the pinned profile expanded for `dir`,
 * then -MMD -MP -MF dep -MT target, -c or -E, -o out, the source. */
static bool vrt_gcc(const struct vrt_fx *f, const char *dir,
                    const char *target, bool preprocess, const char *out,
                    const char *dep, const char *err)
{
    struct vr_bytes raw = {0};
    struct vr_profile *p = calloc(1, sizeof(*p));
    bool ok = p && vrt_read(f->profile, &raw) &&
              vr_profile_load(&raw, dir, p) == NULL;
    char *argv[VR_PROFILE_TOKENS + 16u];
    size_t n = 0;
    argv[n++] = "/usr/bin/cc";
    for (size_t i = 1; ok && i < VR_PROFILE_TOKENS; i++) argv[n++] = p->tokens[i];
    char *tail[] = {"-MMD", "-MP", "-MF", (char *)dep, "-MT", (char *)target,
                    preprocess ? "-fno-working-directory" : "-c",
                    preprocess ? "-E" : "-o", preprocess ? "-o" : (char *)out,
                    preprocess ? (char *)out : VRT_SOURCE,
                    preprocess ? VRT_SOURCE : NULL};
    for (size_t i = 0; i < sizeof(tail) / sizeof(tail[0]) && tail[i]; i++)
        argv[n++] = tail[i];
    argv[n] = NULL;
    ok = ok && vrt_run(dir, argv, vrt_fixed_env, err) == 0;
    free(raw.p);
    free(p);
    return ok;
}

/* ── the fixture world ─────────────────────────────────────────────────── */

static bool vrt_system_key_temp_create(char *out, size_t cap)
{
    const char *prior = getenv("TMPDIR");
    char saved[PATH_MAX];
    if (prior) {
        int n = snprintf(saved, sizeof(saved), "%s", prior);
        if (n < 0 || (size_t)n >= sizeof(saved)) return false;
    }
    /* Key path validation checks every ancestor; the proof checkout may be
     * group writable. Use the system temp root, as test_verify_attest does. */
    if (unsetenv("TMPDIR") != 0) return false;
    bool created = platform_temp_directory_create("z23-vrecv-key-", out, cap);
    bool restored = prior ? setenv("TMPDIR", saved, 1) == 0
                          : unsetenv("TMPDIR") == 0;
    return created && restored;
}

static void vrt_roots(struct zcl_fixed_result_v2_roots *pins)
{
    memset(pins, 0, sizeof(*pins));
    for (size_t i = 0; i < ZCL_FR_ROOT_COUNT; i++)
        memset(zcl_fr_root_slot(pins, i), (int)(0x20u + i), 32u);
    (void)zcl_hex_decode_lower(ZCL_FR_PROFILE_SHA3, pins->profile_args, 32u);
    zcl_fr_env_fixed_root(pins->environment);
}

static bool vrt_dirs(struct vrt_fx *f)
{
    char temporary[PATH_MAX], key_temporary[PATH_MAX], site[PATH_MAX];
    char *made = test_mkdtemp(temporary, sizeof(temporary), "z23-vrecv");
    bool key_made = vrt_system_key_temp_create(key_temporary,
                                                sizeof(key_temporary));
    char *site_made = test_mkdtemp(site, sizeof(site), "z23-vrecv-site");
    if (!getcwd(f->cwd, sizeof(f->cwd)) || !made || !key_made || !site_made ||
        !realpath(site_made, f->anchor) || chmod(f->anchor, 0755) != 0 ||
        !realpath(made, f->root) || !realpath(key_temporary, f->key_root))
        return false;
    struct { char *out; const char *base; const char *name; } paths[] = {
        {f->gen, f->root, "gen"}, {f->donor, f->root, "donor"},
        {f->probe, f->root, "probe"}, {f->vstore, f->anchor, "var/lib/z23verify"},
        {f->etc, f->anchor, "etc/z23verify"},
        {f->store, f->vstore, "store"}, {f->work, f->root, "work"},
        {f->bin, f->root, "bin"}, {f->counter, f->root, "cc.count"},
        {f->phases, f->root, "phases.txt"}, {f->zstore, f->root, "zccstore"},
        {f->pubfile, f->key_root, "verifier.pub"},
        {f->zcc, f->cwd, "build/bin/zcc"},
        {f->profile, f->cwd, "tools/verify/fixed_result_fast.args"},
    };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++)
        if (!vrt_path(paths[i].out, paths[i].base, paths[i].name)) return false;
    const char *dirs[] = {f->gen, f->donor, f->probe, f->store, f->bin,
                          f->zstore, f->etc};
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++)
        if (!vrt_mkdirs(dirs[i])) return false;
    return true;
}

/* The files the real -E of result.c reads in this checkout, copied into
 * the receiver generation and the verifier's source directory. */
static bool vrt_sources(struct vrt_fx *f)
{
    char out[PATH_MAX], dep[PATH_MAX];
    struct vr_bytes d = {0};
    bool ok = vrt_path(out, f->probe, "probe.i") &&
              vrt_path(dep, f->probe, "probe.d") &&
              vrt_gcc(f, f->cwd, ZCL_VERIFY_RECEIVER_PLACEHOLDER_TARGET, true,
                      out, dep, NULL) &&
              vrt_read(dep, &d) &&
              zcl_verify_receiver_depfile_inputs(
                  d.p, d.n, ZCL_VERIFY_RECEIVER_PLACEHOLDER_TARGET, &f->inputs,
                  &f->input_count) == NULL;
    for (size_t i = 0; ok && i < f->input_count; i++) {
        char from[PATH_MAX], to_gen[PATH_MAX], to_donor[PATH_MAX];
        ok = vrt_path(from, f->cwd, f->inputs[i]) &&
             vrt_path(to_gen, f->gen, f->inputs[i]) &&
             vrt_path(to_donor, f->donor, f->inputs[i]) &&
             vrt_copy(from, to_gen) && vrt_copy(from, to_donor);
    }
    free(d.p);
    return ok;
}

/* What the verifier's worker produces in its own cwd, for another epoch. */
static bool vrt_donor_compile(struct vrt_fx *f)
{
    char out[PATH_MAX], dep[PATH_MAX], err[PATH_MAX], pp[PATH_MAX];
    char ppd[PATH_MAX];
    test_vc_target(f->donor_target, 'b');
    struct vr_bytes pp_bytes = {0};
    bool ok = vrt_path(out, f->probe, "donor.o") &&
              vrt_path(dep, f->probe, "donor.d") &&
              vrt_path(err, f->probe, "donor.stderr") &&
              vrt_path(pp, f->probe, "donor.i") &&
              vrt_path(ppd, f->probe, "donor.pp.d") &&
              vrt_write(err, "", 0, 0600) &&
              vrt_gcc(f, f->donor, f->donor_target, true, pp, ppd, NULL) &&
              vrt_gcc(f, f->donor, f->donor_target, false, out, dep, err) &&
              vrt_read(out, &f->obj) && vrt_read(dep, &f->dep) &&
              vrt_read(err, &f->err) && vrt_read(pp, &pp_bytes) &&
              vrt_same_file(dep, ppd);
    if (ok) zcl_sha3_256(pp_bytes.p, pp_bytes.n, f->pp);
    f->pp_len = pp_bytes.n;
    free(pp_bytes.p);
    return ok;
}

/* The signer's expected key: the same profile expanded for its jail cwd
 * /zclassic23 and the worker's /work scratch paths. */
static bool vrt_signer_key(struct vrt_fx *f)
{
    struct vr_bytes raw = {0};
    struct vr_profile *p = calloc(1, sizeof(*p));
    static const char *const env[] = {
        "LC_ALL=C", "TZ=UTC", "TMPDIR=/tmp", "PATH=/usr/bin:/bin"};
    bool ok = p && vrt_read(f->profile, &raw) &&
              vr_profile_load(&raw, ZCL_FR_CWD, p) == NULL;
    const char *argv[VR_PROFILE_TOKENS + 10u];
    size_t n = 0;
    for (size_t i = 0; ok && i < VR_PROFILE_TOKENS; i++) argv[n++] = p->tokens[i];
    const char *tail[] = {"-MMD", "-MP", "-MF", "/work/result.ABC123/deps.d",
                          "-MT", f->donor_target, "-c", "-o",
                          "/work/result.ABC123/result.o", VRT_SOURCE};
    for (size_t i = 0; ok && i < 10u; i++) argv[n++] = tail[i];
    const char *why = NULL;
    ok = ok && zcl_fixed_result_expected_v2(
                   &f->pins, f->pins.source_content, f->pp, f->donor_target,
                   raw.p, raw.n, ZCL_FR_CWD, argv, n, env, 4u, -1, &f->signer,
                   &why);
    if (!ok && why) fprintf(stderr, "verify receiver signer key: %s\n", why);
    free(raw.p);
    free(p);
    return ok;
}

static void vrt_digest(struct zcl_fr_artifact_digest *d, const struct vr_bytes *b)
{
    d->size = b->n;
    zcl_sha3_256(b->p, b->n, d->sha3);
}

static bool vrt_receipt(struct vrt_fx *f, const struct zcl_fixed_result_v2_roots *pins)
{
    struct zcl_fr_receipt r;
    memset(&r, 0, sizeof(r));
    memcpy(r.launch_id, "00112233445566778899aabbccddeeff", ZCL_FR_ID_LEN);
    memcpy(r.request_nonce, "ffeeddccbbaa99887766554433221100", ZCL_FR_ID_LEN);
    memcpy(r.target, f->donor_target, sizeof(r.target));
    (void)snprintf(r.toolchain_id, sizeof(r.toolchain_id), "%s",
                   f->signer.toolchain_id);
    r.pins = *pins;
    memcpy(r.scratch, "/work/result.ABC123", ZCL_FR_SCRATCH_LEN);
    memset(r.compile_argv_sha3, 0x61, 32u);
    memset(r.preprocess_argv_sha3, 0x62, 32u);
    r.mount_namespace_dev = 4u;
    r.mount_namespace_ino = 4026531840u;
    vrt_digest(&r.artifacts[0], &f->obj);
    vrt_digest(&r.artifacts[1], &f->dep);
    vrt_digest(&r.artifacts[2], &f->err);
    r.artifacts[3].size = f->pp_len;
    memcpy(r.artifacts[3].sha3, f->pp, 32u);
    const char *why = NULL;
    bool ok = zcl_fr_receipt_encode(&r, f->receipt, sizeof(f->receipt),
                                    &f->receipt_len, &why);
    if (!ok) fprintf(stderr, "verify receiver receipt: %s\n", why);
    return ok;
}

static struct zcl_verify_attest_record vrt_record(const struct vrt_fx *f,
                                                  int exit_code)
{
    struct zcl_verify_attest_record r;
    memset(&r, 0, sizeof(r));
    r.binding.contract = (struct zcl_verify_attest_text){
        ZCL_FR_CONTRACT, sizeof(ZCL_FR_CONTRACT) - 1u};
    memcpy(r.binding.profile_sha3, f->pins.profile_args, 32u);
    r.binding.target = (struct zcl_verify_attest_text){f->donor_target,
                                                       ZCL_FR_TARGET_LEN};
    zcl_sha3_256(f->receipt, f->receipt_len, r.binding.receipt_sha3);
    r.toolchain_id = f->signer.expected.toolchain_id;
    r.argv_norm = f->signer.expected.argv_norm;
    r.recorded_cwd = f->signer.expected.recorded_cwd;
    memcpy(r.pp_sha3, f->pp, 32u);
    memcpy(r.closure_sha3, f->signer.expected.closure_sha3, 32u);
    zcl_sha3_256(f->obj.p, f->obj.n, r.obj_sha3);
    zcl_sha3_256(f->dep.p, f->dep.n, r.dep_sha3);
    zcl_sha3_256(f->err.p, f->err.n, r.stderr_sha3);
    r.exit_code = exit_code;
    return r;
}

/* One observation directory under the fixture store: the record's bytes
 * name it, beside the object, depfile, stderr and launch receipt. */
static bool vrt_observe(const struct vrt_fx *f, const uint8_t *record,
                        size_t record_len, const struct vr_bytes *obj,
                        char name[65])
{
    uint8_t hash[32];
    char dir[PATH_MAX], path[PATH_MAX];
    zcl_sha3_256(record, record_len, hash);
    zcl_hex_encode(hash, sizeof(hash), name);
    return vrt_path(dir, f->key_dir, name) && mkdir(dir, 0755) == 0 &&
           vrt_path(path, dir, "attest.bin") &&
           vrt_write(path, record, record_len, 0644) &&
           vrt_path(path, dir, "object.o") &&
           vrt_write(path, obj->p, obj->n, 0644) &&
           vrt_path(path, dir, "deps.d") &&
           vrt_write(path, f->dep.p, f->dep.n, 0644) &&
           vrt_path(path, dir, "stderr.bin") &&
           vrt_write(path, f->err.p, f->err.n, 0644) &&
           vrt_path(path, dir, "launch.bin") &&
           vrt_write(path, f->receipt, f->receipt_len, 0644);
}

static bool vrt_publish(const struct vrt_fx *f, int exit_code, char name[65])
{
    struct zcl_verify_attest_record rec = vrt_record(f, exit_code);
    uint8_t *bytes = NULL;
    size_t len = 0;
    const char *why = NULL;
    bool ok = zcl_verify_attest_seal(&rec, vrt_seed, &bytes, &len, &why) &&
              vrt_observe(f, bytes, len, &f->obj, name);
    free(bytes);
    return ok;
}

static bool vrt_unpublish(const struct vrt_fx *f, const char *name)
{
    char dir[PATH_MAX], path[PATH_MAX];
    const char *files[] = {"attest.bin", "object.o", "deps.d", "stderr.bin",
                           "launch.bin"};
    if (!vrt_path(dir, f->key_dir, name)) return false;
    for (size_t i = 0; i < 5u; i++)
        if (!vrt_path(path, dir, files[i]) ||
            (unlink(path) != 0 && errno != ENOENT))
            return false;
    return rmdir(dir) == 0;
}

static bool vrt_store(struct vrt_fx *f)
{
    char locks[PATH_MAX], lock[PATH_MAX], key[ZCL_VERIFY_ATTEST_STORE_KEY_HEX];
    const struct zcl_verify_attest_expected *e = &f->signer.expected;
    zcl_verify_attest_store_key_hex(&e->toolchain_id, &e->argv_norm,
                                    &e->recorded_cwd, e->pp_sha3,
                                    e->closure_sha3, key);
    return vrt_path(locks, f->vstore, "locks") && mkdir(locks, 0755) == 0 &&
           vrt_path(lock, locks, "fixed_result.lock") &&
           vrt_write(lock, "", 0, 0644) && vrt_path(f->key_dir, f->store, key) &&
           mkdir(f->key_dir, 0755) == 0;
}

/* Production's site layout under the test anchor: the pins and the store
 * policy in anchor/etc/z23verify, both 0444, the test uid standing in for
 * root as the site owner and, under the waiver, as signer too. */
static bool vrt_site_file(const struct vrt_fx *f, const char *name,
                          char out[PATH_MAX])
{
    return vrt_path(out, f->etc, name);
}

static bool vrt_site(const struct vrt_fx *f,
                     const struct zcl_fixed_result_v2_roots *pins)
{
    uint8_t bytes[2048];
    size_t len = 0;
    const char *why = NULL;
    char path[PATH_MAX], text[96];
    unsigned me = (unsigned)geteuid();
    int n = snprintf(text, sizeof(text),
                     "z23verify.store.v1\nsigner_uid=%u\npublisher_uid=%u\n",
                     me, me);
    return n > 0 && n < (int)sizeof(text) &&
           zcl_fr_pins_encode(pins, bytes, sizeof(bytes), &len, &why) &&
           vrt_site_file(f, "fixed_result.pins", path) &&
           vrt_write(path, bytes, len, 0444) &&
           vrt_site_file(f, "store.policy", path) &&
           vrt_write(path, text, (size_t)n, 0444);
}

static bool vrt_key(struct vrt_fx *f)
{
    uint8_t pub[32], secret[32];
    char hex[66];
    ed25519_keypair(pub, secret, vrt_seed);
    zcl_hex_encode(pub, 32, hex);
    hex[64] = '\n';
    hex[65] = 0;
    f->box = (struct zcl_verify_attest_box_key){.known = true, .present = false};
    return vrt_write(f->pubfile, hex, 65, 0644) &&
           setenv(VRT_KEY_ENV, f->pubfile, 1) == 0;
}

/* A compiler that counts its own launches before it runs the real one. */
static bool vrt_counter_cc(const struct vrt_fx *f)
{
    char script[PATH_MAX * 2], path[PATH_MAX];
    int n = snprintf(script, sizeof(script),
                     "#!/bin/sh\nprintf 'x\\n' >> '%s'\nexec /usr/bin/cc \"$@\"\n",
                     f->counter);
    return n > 0 && n < (int)sizeof(script) && vrt_path(path, f->bin, "cc") &&
           vrt_write(path, script, (size_t)n, 0755) &&
           vrt_write(f->counter, "", 0, 0600);
}

static unsigned vrt_launches(const struct vrt_fx *f)
{
    struct vr_bytes b = {0};
    unsigned n = 0;
    if (vrt_read(f->counter, &b))
        for (size_t i = 0; i < b.n; i++) n += b.p[i] == '\n';
    free(b.p);
    return n;
}

static bool vrt_step(bool ok, const char *step)
{
    if (!ok) fprintf(stderr, "verify receiver fixture: %s failed\n", step);
    return ok;
}

static bool vrt_fixture_make(struct vrt_fx *f)
{
    memset(f, 0, sizeof(*f));
    if (!vrt_step(vrt_dirs(f), "dirs") || !vrt_step(vrt_sources(f), "sources") ||
        !vrt_step(vrt_donor_compile(f), "donor compile"))
        return false;
    vrt_roots(&f->pins);
    int donor_fd = open(f->donor, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    bool ok = donor_fd >= 0 &&
              zcl_verify_receiver_source_content(
                  donor_fd, f->inputs, f->input_count,
                  f->pins.source_content) == NULL;
    if (donor_fd >= 0) (void)close(donor_fd);
    f->fixture = (struct zcl_verify_receiver_fixture){
        .site_anchor = f->anchor, .allow_same_uid = true,
        .profile_path = f->profile, .compiler = NULL};
    return vrt_step(ok, "source content") &&
           vrt_step(vrt_signer_key(f), "signer key") &&
           vrt_step(vrt_receipt(f, &f->pins), "receipt") &&
           vrt_step(vrt_store(f), "store") &&
           vrt_step(vrt_site(f, &f->pins), "site pins and policy") &&
           vrt_step(vrt_key(f), "key") &&
           vrt_step(vrt_counter_cc(f), "counting compiler") &&
           vrt_step(vrt_publish(f, 0, f->pass_name), "publish");
}

/* ── the real zcc epoch publisher in the generation ────────────────────── */

struct vrt_zcc_env {
    bool verified;
    bool admitted;
    const char *admitted_dir; /* NULL: the fixture work directory */
    const char *zcc_dir;      /* NULL: <root>/zccstore */
    /* NULL: build/test-obj and platform/modules/base/src/result.o. When
     * either is set the output buffer must hold PATH_MAX bytes. */
    const char *obj_root;
    const char *obj_leaf;
    const char *cwd; /* NULL: the generation; argv stays the generation's */
};

static bool vrt_output(const struct vrt_zcc_env *z, const char *epoch,
                       char epoch_fill, char *output)
{
    if (!z->obj_root && !z->obj_leaf) {
        test_vc_target(output, epoch_fill);
        return true;
    }
    return snprintf(output, PATH_MAX, "%s/epochs/%s/%s",
                    z->obj_root ? z->obj_root : "build/test-obj", epoch,
                    z->obj_leaf ? z->obj_leaf
                                : "platform/modules/base/src/result.o") <
           PATH_MAX;
}

static bool vrt_session(const struct vrt_fx *f, char epoch_fill,
                        const struct vrt_zcc_env *z, char *output,
                        char session[PATH_MAX])
{
    char epoch[65], dir[PATH_MAX], path[PATH_MAX], admission[PATH_MAX];
    const char *root = z->obj_root ? z->obj_root : "build/test-obj";
    const char *cwd = z->cwd ? z->cwd : f->gen;
    memset(epoch, epoch_fill, 64u);
    epoch[64] = 0;
    char text[512];
    int n = snprintf(text, sizeof(text),
                     "schema=zcl.build_epoch_session.v1\nsource_id=%s\n"
                     "complete=1\nmutation=%s\ncompiler_id=%s\nepoch=%s\n"
                     "profile=test-fast-v2\nflags_sha256=%s\n",
                     VRT_HEX_A, VRT_HEX_A, VRT_HEX_A, epoch, VRT_HEX_A);
    return n > 0 && n < (int)sizeof(text) &&
           vrt_output(z, epoch, epoch_fill, output) &&
           snprintf(session, PATH_MAX, "%s/epochs/%s/.build-session", root,
                    epoch) < PATH_MAX &&
           snprintf(dir, sizeof(dir), "%s/%s/epochs/%s", cwd, root,
                    epoch) < (int)sizeof(dir) &&
           snprintf(admission, sizeof(admission), "%s/%s/.epoch-admission",
                    cwd, root) < (int)sizeof(admission) &&
           vrt_mkdirs(dir) && vrt_mkdirs(admission) &&
           vrt_path(path, cwd, session) &&
           vrt_write(path, text, (size_t)n, 0600);
}

static bool vrt_zcc_env(const struct vrt_fx *f, const struct vrt_zcc_env *z,
                        char storage[6][PATH_MAX + 32], char *envp[10])
{
    size_t n = 0;
    envp[n++] = "LC_ALL=C";
    envp[n++] = "TZ=UTC";
    envp[n++] = "TMPDIR=/tmp";
    bool ok = snprintf(storage[0], sizeof(storage[0]), "PATH=%s:/usr/bin:/bin",
                       f->bin) < (int)sizeof(storage[0]) &&
              snprintf(storage[1], sizeof(storage[1]), "ZCC_DIR=%s",
                       z->zcc_dir ? z->zcc_dir : f->zstore) <
                  (int)sizeof(storage[1]) &&
              snprintf(storage[2], sizeof(storage[2]), "ZCC_ADMITTED=%s",
                       z->admitted_dir ? z->admitted_dir : f->work) <
                  (int)sizeof(storage[2]) &&
              snprintf(storage[3], sizeof(storage[3]), "ZCC_LOG=%s/%s", f->work,
                       "zcc.log") < (int)sizeof(storage[3]);
    envp[n++] = storage[0];
    envp[n++] = storage[1];
    envp[n++] = storage[3];
    if (z->verified) envp[n++] = "ZCC_VERIFIED=1";
    if (z->admitted) envp[n++] = storage[2];
    envp[n] = NULL;
    return ok;
}

/* zcc --epoch-object dep <target> result.c ... -- zcc cc <profile...>, as
 * the Makefile's test-fast object rule runs it. */
static int vrt_zcc(const struct vrt_fx *f, char epoch_fill,
                   const struct vrt_zcc_env *z, char *output)
{
    char session[PATH_MAX], storage[6][PATH_MAX + 32], epoch[65];
    char *envp[10];
    struct vr_bytes raw = {0};
    struct vr_profile *p = calloc(1, sizeof(*p));
    memset(epoch, epoch_fill, 64u);
    epoch[64] = 0;
    bool ok = p && vrt_session(f, epoch_fill, z, output, session) &&
              vrt_zcc_env(f, z, storage, envp) && vrt_read(f->profile, &raw) &&
              vr_profile_load(&raw, f->gen, p) == NULL;
    char *argv[VR_PROFILE_TOKENS + 16u];
    size_t n = 0;
    char *head[] = {(char *)f->zcc, "--epoch-object", "dep", output, VRT_SOURCE,
                    VRT_HEX_A, "1", VRT_HEX_A, epoch, VRT_HEX_A, session, "--",
                    (char *)f->zcc};
    for (size_t i = 0; i < sizeof(head) / sizeof(head[0]); i++) argv[n++] = head[i];
    for (size_t i = 0; ok && i < VR_PROFILE_TOKENS; i++) argv[n++] = p->tokens[i];
    argv[n] = NULL;
    char err[PATH_MAX];
    int rc = ok && vrt_path(err, f->root, "zcc.stderr")
                 ? vrt_run(z->cwd ? z->cwd : f->gen, argv, envp, err) : -1;
    free(raw.p);
    free(p);
    return rc;
}

static bool vrt_published(const struct vrt_fx *f, const char *output,
                          struct vr_bytes *obj)
{
    char path[PATH_MAX];
    return vrt_path(path, f->gen, output) && vrt_read(path, obj);
}

static int64_t vrt_now_us(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static int64_t vrt_child_cpu_us(void)
{
    struct rusage ru;
    if (getrusage(RUSAGE_CHILDREN, &ru) != 0) return 0;
    return (int64_t)(ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) * 1000000 +
           (int64_t)(ru.ru_utime.tv_usec + ru.ru_stime.tv_usec);
}

struct vrt_cost {
    int64_t wall_us, cpu_us;
    uint64_t bytes;
    unsigned launches;
};

/* One epoch-object run with its wall, child CPU and launches measured. */
static int vrt_zcc_measured(struct vrt_fx *f, char epoch_fill,
                            const struct vrt_zcc_env *z,
                            char output[ZCL_FR_TARGET_LEN + 1u],
                            struct vrt_cost *cost)
{
    unsigned before = vrt_launches(f);
    int64_t wall0 = vrt_now_us(), cpu0 = vrt_child_cpu_us();
    int rc = vrt_zcc(f, epoch_fill, z, output);
    cost->wall_us = vrt_now_us() - wall0;
    cost->cpu_us = vrt_child_cpu_us() - cpu0;
    cost->launches = vrt_launches(f) - before;
    struct vr_bytes obj = {0};
    char dep[ZCL_FR_TARGET_LEN + 1u];
    memcpy(dep, output, sizeof(dep));
    dep[ZCL_FR_TARGET_LEN - 1u] = 'd';
    cost->bytes = 0;
    if (vrt_published(f, output, &obj)) cost->bytes += obj.n;
    if (vrt_published(f, dep, &obj)) cost->bytes += obj.n;
    free(obj.p);
    return rc;
}

static bool vrt_prepare(struct vrt_fx *f, struct zcl_verify_receiver *r)
{
    zcl_verify_receiver_prepare_fixture(f->gen, f->work, &f->box, &f->fixture, r);
    return true;
}

static bool vrt_is(const struct zcl_verify_receiver *r,
                   enum zcl_verify_receiver_verdict verdict, const char *reason)
{
    char text[256];
    bool ok = r->verdict == verdict &&
              (reason ? r->reason && strcmp(r->reason, reason) == 0
                      : r->reason == NULL);
    if (!ok && zcl_verify_receiver_admit_text(r, text, sizeof(text)))
        fprintf(stderr, "verify receiver: got %s, want %d(%s)\n", text,
                (int)verdict, reason ? reason : "-");
    return ok;
}

/* Prepare, expect COLD for `reason`, release. */
static bool vrt_cold(struct vrt_fx *f, const char *reason)
{
    struct zcl_verify_receiver r;
    vrt_prepare(f, &r);
    bool ok = vrt_is(&r, ZCL_VERIFY_RECEIVER_COLD, reason) && r.lock_fd < 0;
    zcl_verify_receiver_release(&r);
    return ok;
}

static bool vrt_text_has(const char *path, const char *needle)
{
    struct vr_bytes b = {0};
    bool ok = vrt_read(path, &b);
    char *text = ok ? malloc(b.n + 1u) : NULL;
    if (text) {
        memcpy(text, b.p, b.n);
        text[b.n] = 0;
    }
    ok = text && strstr(text, needle) != NULL;
    free(text);
    free(b.p);
    return ok;
}

static bool vrt_log_has(const struct vrt_fx *f, const char *needle)
{
    char log[PATH_MAX];
    return vrt_path(log, f->work, ZCL_VERIFY_RECEIVER_LOG) &&
           vrt_text_has(log, needle);
}

/* The served object linked into a program that calls it. */
static bool vrt_link_run(const struct vrt_fx *f, const char *object_rel)
{
    static const char main_c[] =
        "#include \"base/result.h\"\n#include <string.h>\n"
        "int main(void) {\n"
        "    struct zcl_result r = zcl_result_make(7, \"f\", 3, \"v=%d\", 42);\n"
        "    return r.code == 7 && !r.ok && strcmp(r.message, \"v=42\") == 0"
        " ? 0 : 1;\n}\n";
    char main_path[PATH_MAX], exe[PATH_MAX], inc[PATH_MAX], obj[PATH_MAX];
    char inc_flag[PATH_MAX + 2];
    if (!vrt_path(main_path, f->root, "main.c") ||
        !vrt_path(exe, f->root, "linked") ||
        !vrt_path(inc, f->cwd, "platform/modules/base/include") ||
        !vrt_path(obj, f->gen, object_rel) ||
        snprintf(inc_flag, sizeof(inc_flag), "-I%s", inc) >= (int)sizeof(inc_flag) ||
        !vrt_write(main_path, main_c, sizeof(main_c) - 1u, 0600))
        return false;
    char *link[] = {"/usr/bin/cc", "-std=c23", "-fPIE", "-pie", inc_flag,
                    "-o", exe, main_path, obj, NULL};
    char *run[] = {exe, NULL};
    return vrt_run(f->root, link, vrt_fixed_env, NULL) == 0 &&
           vrt_run(f->root, run, vrt_fixed_env, NULL) == 0;
}

static bool vrt_obj_is(const struct vrt_fx *f, const char *output,
                       const struct vr_bytes *want)
{
    struct vr_bytes got = {0};
    bool ok = vrt_published(f, output, &got) && got.n == want->n &&
              memcmp(got.p, want->p, got.n) == 0;
    free(got.p);
    return ok;
}

static bool vrt_dep_tail_equal(const struct vrt_fx *f, const char *a,
                               const char *b)
{
    char da[ZCL_FR_TARGET_LEN + 1u], db[ZCL_FR_TARGET_LEN + 1u];
    struct vr_bytes x = {0}, y = {0};
    memcpy(da, a, sizeof(da));
    memcpy(db, b, sizeof(db));
    da[ZCL_FR_TARGET_LEN - 1u] = db[ZCL_FR_TARGET_LEN - 1u] = 'd';
    bool ok = vrt_published(f, da, &x) && vrt_published(f, db, &y) &&
              x.n == y.n && x.n > ZCL_FR_TARGET_LEN &&
              memcmp(x.p, a, ZCL_FR_TARGET_LEN) == 0 &&
              memcmp(y.p, b, ZCL_FR_TARGET_LEN) == 0 &&
              memcmp(x.p + ZCL_FR_TARGET_LEN, y.p + ZCL_FR_TARGET_LEN,
                     x.n - ZCL_FR_TARGET_LEN) == 0;
    free(x.p);
    free(y.p);
    return ok;
}

/* ── 1. hit, measured against a cold compile ──────────────────────────── */

static int vrt_test_hit(struct vrt_fx *f)
{
    int failures = 0;
    struct zcl_verify_receiver r;
    memset(&r, 0, sizeof(r));
    r.lock_fd = -1;
    TEST("verify receiver: admitted object served without a compiler launch") {
        char hit_out[ZCL_FR_TARGET_LEN + 1u], cold_out[ZCL_FR_TARGET_LEN + 1u];
        struct vrt_cost hit = {0}, cold = {0};
        int64_t prep0 = vrt_now_us();
        vrt_prepare(f, &r);
        int64_t prep_wall = vrt_now_us() - prep0;
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_ADMITTED, NULL));
        ASSERT(r.lock_fd >= 0);
        const struct vrt_zcc_env admitted = {.verified = true, .admitted = true};
        ASSERT(vrt_zcc_measured(f, 'c', &admitted, hit_out, &hit) == 0);
        ASSERT(hit.launches == 0);
        ASSERT(vrt_log_has(f, "VERIFIED admitted:fixed_result.v2"));
        zcl_verify_receiver_finish(&r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_HIT, NULL));
        ASSERT(r.launches_avoided == 1u && r.compile_launches == 0u);
        ASSERT(r.lock_fd < 0);
        ASSERT(zcl_verify_receiver_phases_write(&r, f->phases));
        char want[256];
        ASSERT(snprintf(want, sizeof(want), "object_reuse_admit=hit(%s,%s)",
                        r.store_key, r.record_sha3) < (int)sizeof(want));
        ASSERT(vrt_text_has(f->phases, want));
        ASSERT(vrt_text_has(f->phases, "compile_launches_avoided=1"));
        ASSERT(vrt_text_has(f->phases, "object_reuse_cost=wall_us="));
        ASSERT(vrt_obj_is(f, hit_out, &f->obj));

        const struct vrt_zcc_env verified = {.verified = true};
        ASSERT(vrt_zcc_measured(f, 'd', &verified, cold_out, &cold) == 0);
        ASSERT(cold.launches == 1);
        ASSERT(vrt_obj_is(f, cold_out, &f->obj));
        ASSERT(vrt_dep_tail_equal(f, hit_out, cold_out));
        ASSERT(vrt_link_run(f, hit_out));
        printf("verify_receiver measure: cold wall_us=%lld cpu_us=%lld "
               "launches=%u bytes=%llu | hit wall_us=%lld cpu_us=%lld "
               "launches=%u bytes=%llu | receiver wall_us=%lld cpu_us=%lld "
               "bytes=%llu prepare_wall_us=%lld launches_avoided=%u\n",
               (long long)cold.wall_us, (long long)cold.cpu_us, cold.launches,
               (unsigned long long)cold.bytes, (long long)hit.wall_us,
               (long long)hit.cpu_us, hit.launches,
               (unsigned long long)hit.bytes, (long long)r.wall_us,
               (long long)r.cpu_us, (unsigned long long)r.bytes,
               (long long)prep_wall, r.launches_avoided);
        PASS();
    } _test_next:;
    zcl_verify_receiver_release(&r);
    return failures;
}

/* ── 2. every refusal compiles cold, by name ──────────────────────────── */

static void vrt_u32(uint8_t *out, size_t *n, uint32_t v)
{
    for (size_t i = 0; i < 4u; i++) out[(*n)++] = (uint8_t)(v >> (8u * i));
}

/* The retired v1 layout of this observation, signed by the same key: it
 * parses, and admission refuses it by name. */
static bool vrt_publish_v1(const struct vrt_fx *f, char name[65])
{
    static const char schema[] = "zcl.verify_attest.v1";
    static const char domain[] = "zcl.verify_attest.sig.v1";
    const struct zcl_verify_attest_expected *e = &f->signer.expected;
    const struct zcl_verify_attest_text *texts[3] = {
        &e->toolchain_id, &e->argv_norm, &e->recorded_cwd};
    size_t cap = 256u + e->toolchain_id.len + e->argv_norm.len +
                 e->recorded_cwd.len + 5u * 32u + 96u;
    uint8_t *rec = malloc(cap), *msg = malloc(cap + sizeof(domain));
    size_t n = 0;
    bool ok = rec && msg;
    if (ok) {
        rec[n++] = (uint8_t)(sizeof(schema) - 1u);
        rec[n++] = 0u;
        memcpy(rec + n, schema, sizeof(schema) - 1u);
        n += sizeof(schema) - 1u;
        for (size_t i = 0; i < 3u; i++) {
            vrt_u32(rec, &n, (uint32_t)texts[i]->len);
            memcpy(rec + n, texts[i]->bytes, texts[i]->len);
            n += texts[i]->len;
        }
        memcpy(rec + n, e->pp_sha3, 32u);
        memcpy(rec + n + 32u, e->closure_sha3, 32u);
        zcl_sha3_256(f->obj.p, f->obj.n, rec + n + 64u);
        zcl_sha3_256(f->dep.p, f->dep.n, rec + n + 96u);
        zcl_sha3_256(f->err.p, f->err.n, rec + n + 128u);
        n += 160u;
        vrt_u32(rec, &n, 0u);
        uint8_t pub[32], secret[32];
        ed25519_keypair(pub, secret, vrt_seed);
        memcpy(msg, domain, sizeof(domain));
        memcpy(msg + sizeof(domain), rec, n);
        memcpy(rec + n, pub, 32u);
        ed25519_sign(rec + n + 32u, msg, sizeof(domain) + n, secret, pub);
        n += 96u;
        ok = vrt_observe(f, rec, n, &f->obj, name);
    }
    free(rec);
    free(msg);
    return ok;
}

/* A record bound to a launch receipt other than the one published. */
static bool vrt_publish_other_receipt(struct vrt_fx *f, char name[65])
{
    uint8_t saved[TEST_VC_RECEIPT_CAP];
    size_t saved_len = f->receipt_len;
    memcpy(saved, f->receipt, sizeof(saved));
    struct zcl_fixed_result_v2_roots other = f->pins;
    other.worker[0] ^= 1u;
    bool ok = vrt_receipt(f, &other);
    struct zcl_verify_attest_record rec = vrt_record(f, 0);
    memcpy(f->receipt, saved, sizeof(saved));
    f->receipt_len = saved_len;
    uint8_t *bytes = NULL;
    size_t len = 0;
    const char *why = NULL;
    ok = ok && zcl_verify_attest_seal(&rec, vrt_seed, &bytes, &len, &why) &&
         vrt_observe(f, bytes, len, &f->obj, name);
    free(bytes);
    return ok;
}

static bool vrt_edit(const struct vrt_fx *f, const char *rel, const char *add,
                     struct vr_bytes *saved)
{
    char path[PATH_MAX];
    struct vr_bytes b = {0};
    bool ok = vrt_path(path, f->gen, rel) && vrt_read(path, saved) &&
              vrt_read(path, &b);
    uint8_t *next = ok ? malloc(b.n + strlen(add)) : NULL;
    if (next) {
        memcpy(next, b.p, b.n);
        memcpy(next + b.n, add, strlen(add));
    }
    ok = next && vrt_write(path, next, b.n + strlen(add), 0644);
    free(next);
    free(b.p);
    return ok;
}

static bool vrt_restore(const struct vrt_fx *f, const char *rel,
                        struct vr_bytes *saved)
{
    char path[PATH_MAX];
    bool ok = vrt_path(path, f->gen, rel) &&
              vrt_write(path, saved->p, saved->n, 0644);
    free(saved->p);
    saved->p = NULL;
    saved->n = 0;
    return ok;
}

/* ── 1b. the launcher's pin is the receiver's measurement ─────────────── */

static bool vrt_chain_root(const char *dir, uint8_t out[32])
{
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    const char *why = fd >= 0 ? zcl_fr_source_chain_root(fd, out) : "open";
    if (fd >= 0) (void)close(fd);
    if (why) fprintf(stderr, "verify receiver chain root %s: %s\n", dir, why);
    return why == NULL;
}

static int vrt_test_pin_equals_receiver(struct vrt_fx *f)
{
    int failures = 0;
    TEST("verify receiver: the launcher's source_content pin equals the "
         "receiver's root for the real result.c chain") {
        uint8_t receiver[32], checkout[32], donor[32], generation[32];
        uint8_t moded[32];
        char path[PATH_MAX];
        ASSERT(f->input_count == ZCL_FR_SOURCE_CHAIN_COUNT);
        for (size_t i = 0; i < ZCL_FR_SOURCE_CHAIN_COUNT; i++)
            ASSERT(strcmp(f->inputs[i], zcl_fr_source_chain[i]) == 0);
        int gen_fd = open(f->gen, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        ASSERT(gen_fd >= 0);
        const char *why = zcl_verify_receiver_source_content(
            gen_fd, f->inputs, f->input_count, receiver);
        (void)close(gen_fd);
        ASSERT(why == NULL);
        ASSERT(vrt_chain_root(f->gen, generation));
        ASSERT(vrt_chain_root(f->cwd, checkout));
        ASSERT(vrt_chain_root(f->donor, donor));
        ASSERT(memcmp(receiver, generation, 32u) == 0);
        ASSERT(memcmp(receiver, checkout, 32u) == 0);
        ASSERT(memcmp(receiver, donor, 32u) == 0);
        ASSERT(memcmp(receiver, f->pins.source_content, 32u) == 0);
        /* Owner and mode are not part of it; one byte is. */
        ASSERT(vrt_path(path, f->gen, VRT_SOURCE));
        ASSERT(chmod(path, 0600) == 0);
        ASSERT(vrt_chain_root(f->gen, moded));
        ASSERT(chmod(path, 0644) == 0);
        ASSERT(memcmp(moded, receiver, 32u) == 0);
        struct vr_bytes saved = {0};
        ASSERT(vrt_edit(f, VRT_SOURCE, " ", &saved));
        ASSERT(vrt_chain_root(f->gen, moded));
        ASSERT(vrt_restore(f, VRT_SOURCE, &saved));
        ASSERT(memcmp(moded, receiver, 32u) != 0);

        /* The definition refuses what it cannot name uniquely. */
        static const uint8_t x[] = "x";
        const uint8_t *bytes[2] = {x, x};
        const size_t lens[2] = {1u, 1u};
        const char *order[2] = {"b", "a"}, *dup[2] = {"a", "a"};
        const char *dot[1] = {"a/../b"}, *abs_path[1] = {"/a"};
        const char *empty[1] = {"a//b"};
        ASSERT(!zcl_fr_source_content_v2(order, bytes, lens, 2u, moded, &why));
        ASSERT(strcmp(why, ZCL_FR_WHY_FIELD_ORDER) == 0);
        ASSERT(!zcl_fr_source_content_v2(dup, bytes, lens, 2u, moded, &why));
        ASSERT(strcmp(why, ZCL_FR_WHY_FIELD_ORDER) == 0);
        ASSERT(!zcl_fr_source_content_v2(dot, bytes, lens, 1u, moded, &why));
        ASSERT(strcmp(why, ZCL_FR_WHY_FIELD_MALFORMED) == 0);
        ASSERT(!zcl_fr_source_content_v2(abs_path, bytes, lens, 1u, moded, &why));
        ASSERT(strcmp(why, ZCL_FR_WHY_FIELD_MALFORMED) == 0);
        ASSERT(!zcl_fr_source_content_v2(empty, bytes, lens, 1u, moded, &why));
        ASSERT(strcmp(why, ZCL_FR_WHY_FIELD_MALFORMED) == 0);
        ASSERT(!zcl_fr_source_content_v2(order, bytes, lens, 0u, moded, &why));
        ASSERT(strcmp(why, ZCL_FR_WHY_ARGUMENTS) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static const char *vrt_header(const struct vrt_fx *f)
{
    for (size_t i = 0; i < f->input_count; i++)
        if (strcmp(f->inputs[i], "platform/modules/base/include/base/result.h") == 0)
            return f->inputs[i];
    return NULL;
}

static int vrt_test_cold_trust(struct vrt_fx *f)
{
    int failures = 0;
    TEST("verify receiver: no key, store, same uid and pins refusals are cold") {
        ASSERT(unsetenv(VRT_KEY_ENV) == 0);
        ASSERT(vrt_cold(f, "no_verifier_key"));
        ASSERT(setenv(VRT_KEY_ENV, f->pubfile, 1) == 0);

        /* Park the store beside itself, in its own parent directory, so the
         * move is a same-directory, same-filesystem rename that never
         * touches the store's ".." entry or a second fixture tree. The
         * errno is printed so a failure under load names its cause. */
        char path[PATH_MAX], away[PATH_MAX], lib[PATH_MAX];
        ASSERT(vrt_path(lib, f->anchor, "var/lib"));
        ASSERT(vrt_path(away, lib, "store-away"));
        int moved = rename(f->vstore, away);
        if (moved != 0) fprintf(stderr, "verify receiver: park store: %s\n", strerror(errno));
        ASSERT(moved == 0);
        ASSERT(vrt_cold(f, "store_path_unsafe"));
        moved = rename(away, f->vstore);
        if (moved != 0) fprintf(stderr, "verify receiver: restore store: %s\n", strerror(errno));
        ASSERT(moved == 0);

        f->fixture.allow_same_uid = false;
        ASSERT(vrt_cold(f, "store_owner_same_uid"));
        f->fixture.allow_same_uid = true;

        ASSERT(vrt_site_file(f, "store.policy", path));
        ASSERT(unlink(path) == 0);
        ASSERT(vrt_cold(f, "store_policy_missing"));
        ASSERT(vrt_site(f, &f->pins));
        ASSERT(vrt_site_file(f, "fixed_result.pins", path));
        ASSERT(unlink(path) == 0);
        ASSERT(vrt_cold(f, "store_pins_missing"));
        ASSERT(vrt_site(f, &f->pins));
        ASSERT(chmod(path, 0644) == 0);
        ASSERT(vrt_cold(f, "store_pins_unsafe"));
        ASSERT(vrt_site(f, &f->pins));

        struct zcl_fixed_result_v2_roots wrong = f->pins;
        wrong.tool_image[0] ^= 1u;
        ASSERT(vrt_site(f, &wrong));
        ASSERT(vrt_cold(f, "attest_no_observation"));
        wrong = f->pins;
        wrong.source_content[0] ^= 1u;
        ASSERT(vrt_site(f, &wrong));
        ASSERT(vrt_cold(f, "receiver_source_content_mismatch"));
        ASSERT(vrt_site(f, &f->pins));
        struct zcl_verify_receiver r;
        vrt_prepare(f, &r);
        bool admitted = vrt_is(&r, ZCL_VERIFY_RECEIVER_ADMITTED, NULL);
        zcl_verify_receiver_release(&r);
        ASSERT(admitted);
        PASS();
    } _test_next:;
    return failures;
}

static int vrt_test_cold_record(struct vrt_fx *f)
{
    int failures = 0;
    TEST("verify receiver: tampered, retired and mis-bound records are cold") {
        char dir[PATH_MAX], path[PATH_MAX], name[65];
        struct vr_bytes junk = {0};
        ASSERT(vrt_path(dir, f->key_dir, f->pass_name));
        ASSERT(vrt_path(path, dir, "object.o"));
        ASSERT(vrt_read(path, &junk));
        junk.p[junk.n / 2u] ^= 0x40u;
        ASSERT(vrt_write(path, junk.p, junk.n, 0644));
        free(junk.p);
        ASSERT(vrt_cold(f, "contract_receipt_artifact_mismatch"));
        ASSERT(vrt_write(path, f->obj.p, f->obj.n, 0644));
        ASSERT(vrt_unpublish(f, f->pass_name));

        ASSERT(vrt_publish_v1(f, name));
        ASSERT(vrt_cold(f, "attest_record_v1_unbound"));
        ASSERT(vrt_unpublish(f, name));

        ASSERT(vrt_publish_other_receipt(f, name));
        ASSERT(vrt_cold(f, "attest_receipt_mismatch"));
        ASSERT(vrt_unpublish(f, name));
        ASSERT(vrt_publish(f, 0, f->pass_name));
        PASS();
    } _test_next:;
    return failures;
}

static int vrt_test_cold_source(struct vrt_fx *f)
{
    int failures = 0;
    TEST("verify receiver: a changed result.c or header is cold") {
        struct vr_bytes saved = {0};
        const char *header = vrt_header(f);
        ASSERT(header != NULL);
        ASSERT(vrt_edit(f, VRT_SOURCE, "/* changed */\n", &saved));
        ASSERT(vrt_cold(f, "receiver_source_content_mismatch"));
        ASSERT(vrt_restore(f, VRT_SOURCE, &saved));
        ASSERT(vrt_edit(f, header, "/* changed */\n", &saved));
        ASSERT(vrt_cold(f, "receiver_source_content_mismatch"));
        ASSERT(vrt_restore(f, header, &saved));
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3. contradictions block ──────────────────────────────────────────── */

static int vrt_test_block(struct vrt_fx *f)
{
    int failures = 0;
    struct zcl_verify_receiver r;
    memset(&r, 0, sizeof(r));
    r.lock_fd = -1;
    TEST("verify receiver: a signed FAIL and a source changed mid-step block") {
        char name[65], out[ZCL_FR_TARGET_LEN + 1u];
        struct vr_bytes saved = {0};
        ASSERT(vrt_unpublish(f, f->pass_name));
        ASSERT(vrt_publish(f, 1, name));
        vrt_prepare(f, &r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_BLOCK, "attest_exit_nonzero"));
        ASSERT(r.lock_fd < 0);
        zcl_verify_receiver_release(&r);
        ASSERT(vrt_unpublish(f, name));
        ASSERT(vrt_publish(f, 0, f->pass_name));

        /* Admitted, then result.c moves before make reads it. */
        vrt_prepare(f, &r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_ADMITTED, NULL));
        ASSERT(vrt_edit(f, VRT_SOURCE, "/* late */\n", &saved));
        const struct vrt_zcc_env admitted = {.verified = true, .admitted = true};
        unsigned before = vrt_launches(f);
        ASSERT(vrt_zcc(f, 'e', &admitted, out) == 0);
        ASSERT(vrt_launches(f) == before);
        zcl_verify_receiver_finish(&r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_BLOCK, "receiver_source_changed"));
        ASSERT(r.launches_avoided == 0u);
        ASSERT(vrt_restore(f, VRT_SOURCE, &saved));
        zcl_verify_receiver_release(&r);

        /* Admitted, then the published object is swapped under make. */
        vrt_prepare(f, &r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_ADMITTED, NULL));
        ASSERT(vrt_zcc(f, 'f', &admitted, out) == 0);
        char path[PATH_MAX];
        ASSERT(vrt_path(path, f->gen, out));
        ASSERT(vrt_write(path, "junk", 4u, 0600));
        zcl_verify_receiver_finish(&r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_BLOCK, "admitted_object_mismatch"));
        PASS();
    } _test_next:;
    zcl_verify_receiver_release(&r);
    return failures;
}

/* ── 3b. depfile tails and the target shape, each layer on its own ───── */

#define VRT_DEP_C "platform/modules/base/src/result.c"
#define VRT_DEP_H "platform/modules/base/include/base/result.h"
#define VRT_DEP_F "platform/modules/base/include/base/format_attribute.h"

/* The donor depfile for its own target with `list` as the prerequisites
 * and the same -MP phony rules. */
static int vrt_dep_text(const struct vrt_fx *f, const char *list, char *out,
                        size_t cap)
{
    return snprintf(out, cap, "%s: %s\n" VRT_DEP_H ":\n" VRT_DEP_F ":\n",
                    f->donor_target, list);
}

/* A validly signed observation whose depfile is `dep`; the fixture's own
 * depfile and receipt are restored afterwards. */
static bool vrt_publish_dep(struct vrt_fx *f, const char *dep, char name[65])
{
    struct vr_bytes saved = f->dep;
    f->dep = (struct vr_bytes){(uint8_t *)dep, strlen(dep)};
    bool ok = vrt_receipt(f, &f->pins) && vrt_publish(f, 0, name);
    f->dep = saved;
    return vrt_receipt(f, &f->pins) && ok;
}

static int vrt_test_depfile_admission(struct vrt_fx *f)
{
    int failures = 0;
    TEST("verify receiver: a signed depfile with the right target and "
         "another dependency list is cold at admission") {
        static const char *const lists[] = {
            "\\\n " VRT_DEP_C " \\\n " VRT_DEP_H " \\\n " VRT_DEP_F,
            "\\\n " VRT_DEP_C " \\\n " VRT_DEP_H,
            "\\\n " VRT_DEP_C " \\\n " VRT_DEP_H " \\\n " VRT_DEP_F
            " \\\n platform/modules/base/include/base/extra.h",
            "\\\n " VRT_DEP_C " \\\n " VRT_DEP_F " \\\n " VRT_DEP_H,
        };
        char dep[1024], name[65];
        /* The template reproduces the real donor depfile exactly, so each
         * variant differs from it in the dependency list alone. */
        int n = vrt_dep_text(f, lists[0], dep, sizeof(dep));
        ASSERT(n > 0 && (size_t)n == f->dep.n && memcmp(dep, f->dep.p, f->dep.n) == 0);
        ASSERT(vrt_unpublish(f, f->pass_name));
        for (size_t i = 1; i < sizeof(lists) / sizeof(lists[0]); i++) {
            n = vrt_dep_text(f, lists[i], dep, sizeof(dep));
            ASSERT(n > 0 && (size_t)n < sizeof(dep));
            ASSERT(vrt_publish_dep(f, dep, name));
            ASSERT(vrt_cold(f, "receiver_depfile_mismatch"));
            ASSERT(vrt_unpublish(f, name));
        }
        ASSERT(vrt_publish(f, 0, f->pass_name));
        PASS();
    } _test_next:;
    return failures;
}

/* The depfile beside a published target, read and replaced with its tail
 * missing one header; `saved` keeps the original for vrt_dep_put_back. */
static bool vrt_dep_drop_header(const struct vrt_fx *f, const char *out,
                                struct vr_bytes *saved)
{
    char rel[ZCL_FR_TARGET_LEN + 1u], path[PATH_MAX];
    static const char drop[] = " \\\n " VRT_DEP_F;
    memcpy(rel, out, sizeof(rel));
    rel[ZCL_FR_TARGET_LEN - 1u] = 'd';
    if (!vrt_path(path, f->gen, rel) || !vrt_read(path, saved) ||
        saved->n <= ZCL_FR_TARGET_LEN)
        return false;
    char *text = malloc(saved->n + 1u);
    if (!text) return false;
    memcpy(text, saved->p, saved->n);
    text[saved->n] = 0;
    char *cut = strstr(text + ZCL_FR_TARGET_LEN, drop);
    size_t n = saved->n;
    if (cut) {
        memmove(cut, cut + sizeof(drop) - 1u, strlen(cut + sizeof(drop) - 1u) + 1u);
        n -= sizeof(drop) - 1u;
    }
    bool ok = cut && vrt_write(path, text, n, 0600);
    free(text);
    return ok;
}

static bool vrt_dep_put_back(const struct vrt_fx *f, const char *out,
                             struct vr_bytes *saved)
{
    char rel[ZCL_FR_TARGET_LEN + 1u], path[PATH_MAX];
    memcpy(rel, out, sizeof(rel));
    rel[ZCL_FR_TARGET_LEN - 1u] = 'd';
    bool ok = vrt_path(path, f->gen, rel) &&
              vrt_write(path, saved->p, saved->n, 0600);
    free(saved->p);
    *saved = (struct vr_bytes){0};
    return ok;
}

static bool vrt_log_write(const struct vrt_fx *f, const char *text)
{
    char log[PATH_MAX];
    return vrt_path(log, f->work, ZCL_VERIFY_RECEIVER_LOG) &&
           vrt_write(log, text, strlen(text), 0600);
}

static int vrt_test_depfile_after_make(struct vrt_fx *f)
{
    int failures = 0;
    struct zcl_verify_receiver r;
    memset(&r, 0, sizeof(r));
    r.lock_fd = -1;
    struct vr_bytes saved = {0};
    char out[ZCL_FR_TARGET_LEN + 1u];
    TEST("verify receiver: a published depfile whose tail differs from the "
         "driver's blocks, whatever the log claims") {
        const struct vrt_zcc_env admitted = {.verified = true, .admitted = true};
        vrt_prepare(f, &r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_ADMITTED, NULL));
        ASSERT(vrt_zcc(f, '5', &admitted, out) == 0);
        ASSERT(vrt_dep_drop_header(f, out, &saved));
        zcl_verify_receiver_finish(&r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_BLOCK, "receiver_depfile_mismatch"));
        ASSERT(r.launches_avoided == 0u);
        zcl_verify_receiver_release(&r);

        /* Served, then the log rewritten to claim a compile instead: the
         * epoch holding the admitted bytes is still rechecked. */
        vrt_prepare(f, &r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_ADMITTED, NULL));
        char line[256];
        ASSERT(snprintf(line, sizeof(line), "MISS     %-28s %s\n",
                        "admitted:argv_mismatch", out) < (int)sizeof(line));
        ASSERT(vrt_log_write(f, line));
        zcl_verify_receiver_finish(&r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_BLOCK, "receiver_depfile_mismatch"));
        zcl_verify_receiver_release(&r);
        ASSERT(vrt_dep_put_back(f, out, &saved));

        /* The same claim with the depfile intact and the source changed. */
        struct vr_bytes source = {0};
        vrt_prepare(f, &r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_ADMITTED, NULL));
        ASSERT(vrt_log_write(f, line));
        ASSERT(vrt_edit(f, VRT_SOURCE, "/* late */\n", &source));
        zcl_verify_receiver_finish(&r);
        ASSERT(vrt_restore(f, VRT_SOURCE, &source));
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_BLOCK, "receiver_source_changed"));
        PASS();
    } _test_next:;
    if (saved.p) (void)vrt_dep_put_back(f, out, &saved);
    zcl_verify_receiver_release(&r);
    return failures;
}

/* An admitted step whose log is missing, oversized, silent or names a
 * target the driver cannot recheck blocks; it never falls back to cold. */
static int vrt_test_admitted_log(struct vrt_fx *f)
{
    int failures = 0;
    struct zcl_verify_receiver r;
    memset(&r, 0, sizeof(r));
    r.lock_fd = -1;
    TEST("verify receiver: an unreadable, silent or malformed log blocks") {
        char log[PATH_MAX], bad[ZCL_FR_TARGET_LEN + 1u], line[256];
        vrt_prepare(f, &r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_ADMITTED, NULL));
        zcl_verify_receiver_finish(&r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_BLOCK, "admitted_log_unreadable"));
        zcl_verify_receiver_release(&r);

        vrt_prepare(f, &r);
        ASSERT(vrt_path(log, f->work, ZCL_VERIFY_RECEIVER_LOG));
        ASSERT(vrt_write(log, "", 0u, 0600));
        ASSERT(truncate(log, (off_t)VR_LOG_MAX + 1) == 0);
        zcl_verify_receiver_finish(&r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_BLOCK, "admitted_log_unreadable"));
        zcl_verify_receiver_release(&r);

        vrt_prepare(f, &r);
        ASSERT(vrt_log_write(f, "MISS     verified:cold                 x\n"));
        zcl_verify_receiver_finish(&r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_BLOCK, "admitted_not_consumed"));
        zcl_verify_receiver_release(&r);

        /* Right length, wrong shape: the driver's own target check. */
        test_vc_target(bad, '8');
        memcpy(bad, "build/TEST", 10u);
        vrt_prepare(f, &r);
        ASSERT(snprintf(line, sizeof(line), "VERIFIED %-28s %s\n",
                        "admitted:fixed_result.v2", bad) < (int)sizeof(line));
        ASSERT(vrt_log_write(f, line));
        zcl_verify_receiver_finish(&r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_BLOCK, "admitted_target_invalid"));
        zcl_verify_receiver_release(&r);

        /* A served path the driver cannot even record. */
        vrt_prepare(f, &r);
        ASSERT(vrt_log_write(f, "VERIFIED admitted:fixed_result.v2 short.o\n"));
        zcl_verify_receiver_finish(&r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_BLOCK, "admitted_target_invalid"));
        PASS();
    } _test_next:;
    zcl_verify_receiver_release(&r);
    return failures;
}

/* The same argv from a sub-make in another tree is not served. */
static int vrt_test_zcc_other_tree(struct vrt_fx *f)
{
    int failures = 0;
    struct zcl_verify_receiver r;
    memset(&r, 0, sizeof(r));
    r.lock_fd = -1;
    TEST("verify receiver: zcc serves only in the driver's generation root") {
        char other[PATH_MAX], out[ZCL_FR_TARGET_LEN + 1u];
        ASSERT(vrt_path(other, f->root, "other-tree"));
        for (size_t i = 0; i < f->input_count; i++) {
            char from[PATH_MAX], to[PATH_MAX];
            ASSERT(vrt_path(from, f->gen, f->inputs[i]));
            ASSERT(vrt_path(to, other, f->inputs[i]));
            ASSERT(vrt_copy(from, to));
        }
        vrt_prepare(f, &r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_ADMITTED, NULL));
        const struct vrt_zcc_env sub = {.verified = true, .admitted = true,
                                        .cwd = other};
        unsigned before = vrt_launches(f);
        ASSERT(vrt_zcc(f, '9', &sub, out) == 0);
        ASSERT(vrt_launches(f) == before + 1u);
        ASSERT(vrt_log_has(f, "MISS     admitted:cwd_mismatch"));
        ASSERT(!vrt_log_has(f, "VERIFIED"));
        zcl_verify_receiver_finish(&r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_COLD, "admitted_cwd_mismatch"));
        PASS();
    } _test_next:;
    zcl_verify_receiver_release(&r);
    return failures;
}

static int vrt_test_zcc_target_shape(struct vrt_fx *f)
{
    int failures = 0;
    struct zcl_verify_receiver r;
    memset(&r, 0, sizeof(r));
    r.lock_fd = -1;
    TEST("verify receiver: zcc itself refuses to serve a wrong target shape") {
        char out[PATH_MAX];
        vrt_prepare(f, &r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_ADMITTED, NULL));
        const struct vrt_zcc_env shapes[] = {
            {.verified = true, .admitted = true, .obj_root = "build/other-obj"},
            {.verified = true, .admitted = true,
             .obj_leaf = "platform/modules/base/src/result2.o"},
        };
        for (size_t i = 0; i < sizeof(shapes) / sizeof(shapes[0]); i++) {
            unsigned before = vrt_launches(f);
            ASSERT(vrt_zcc(f, (char)('6' + i), &shapes[i],
                           out) == 0);
            ASSERT(vrt_launches(f) == before + 1u);
            ASSERT(vrt_obj_is(f, out, &f->obj));
        }
        ASSERT(vrt_log_has(f, "MISS     admitted:target_invalid"));
        ASSERT(!vrt_log_has(f, "VERIFIED"));
        zcl_verify_receiver_finish(&r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_COLD, "admitted_target_invalid"));
        PASS();
    } _test_next:;
    zcl_verify_receiver_release(&r);
    return failures;
}

/* ── 4. nothing without a record is used ──────────────────────────────── */

static bool vrt_junk_file(const char *path)
{
    struct vr_bytes b = {0};
    if (!vrt_read(path, &b)) return false;
    memset(b.p, 0x5a, b.n);
    bool ok = vrt_write(path, b.p, b.n, 0600);
    free(b.p);
    return ok;
}

static size_t vrt_junked;

static int vrt_junk_walk(const char *path, const struct stat *st, int type,
                         struct FTW *walk)
{
    (void)walk;
    if (type == FTW_F && S_ISREG(st->st_mode) && st->st_size > 0)
        return vrt_junk_file(path) && ++vrt_junked ? 0 : 1;
    return 0;
}

static int vrt_test_planted(struct vrt_fx *f)
{
    int failures = 0;
    struct zcl_verify_receiver r;
    memset(&r, 0, sizeof(r));
    r.lock_fd = -1;
    TEST("verify receiver: planted objects without a record are not used") {
        char out[ZCL_FR_TARGET_LEN + 1u], path[PATH_MAX];
        ASSERT(vrt_unpublish(f, f->pass_name));

        /* A private zcc store filled by an ordinary compile, then every
         * cached byte replaced: proof mode compiles the real bytes. */
        const struct vrt_zcc_env cached = {.verified = false};
        ASSERT(vrt_zcc(f, '1', &cached, out) == 0);
        vrt_junked = 0;
        ASSERT(nftw(f->zstore, vrt_junk_walk, 8, FTW_PHYS) == 0);
        ASSERT(vrt_junked > 0);
        vrt_prepare(f, &r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_COLD, "attest_no_observation"));
        unsigned before = vrt_launches(f);
        const struct vrt_zcc_env verified = {.verified = true};
        ASSERT(vrt_zcc(f, '2', &verified, out) == 0);
        ASSERT(vrt_launches(f) == before + 1u);
        ASSERT(vrt_obj_is(f, out, &f->obj));
        zcl_verify_receiver_finish(&r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_COLD, "attest_no_observation"));
        zcl_verify_receiver_release(&r);

        /* An object planted at the epoch target is recompiled over. */
        char epoch[65];
        memset(epoch, '3', 64u);
        epoch[64] = 0;
        test_vc_target(out, '3');
        ASSERT(vrt_path(path, f->gen, out));
        char parent[PATH_MAX];
        ASSERT(snprintf(parent, sizeof(parent), "%s", path) < (int)sizeof(parent));
        *strrchr(parent, '/') = 0;
        ASSERT(vrt_mkdirs(parent));
        ASSERT(vrt_write(path, "planted", 7u, 0600));
        before = vrt_launches(f);
        ASSERT(vrt_zcc(f, '3', &verified, out) == 0);
        ASSERT(vrt_launches(f) == before + 1u);
        ASSERT(vrt_obj_is(f, out, &f->obj));

        /* A planted admitted directory is wiped and refused by prepare, and
         * names nothing the receiver will call a hit. */
        ASSERT(vrt_mkdirs(f->work));
        ASSERT(vrt_path(path, f->work, ZCL_VERIFY_RECEIVER_OBJECT));
        ASSERT(vrt_write(path, f->obj.p, f->obj.n, 0600));
        vrt_prepare(f, &r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_COLD, "attest_no_observation"));
        ASSERT(access(path, F_OK) != 0);
        zcl_verify_receiver_finish(&r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_COLD, "attest_no_observation"));
        zcl_verify_receiver_release(&r);
        ASSERT(vrt_path(path, f->work, "planted-unknown"));
        ASSERT(vrt_mkdirs(f->work));
        ASSERT(vrt_write(path, "x", 1u, 0600));
        ASSERT(vrt_cold(f, "receiver_work_unsafe"));
        ASSERT(unlink(path) == 0 && rmdir(f->work) == 0);

        /* make's compiler argv differs from the pinned profile: zcc
         * compiles, and the receiver reports why the object went unused. */
        ASSERT(vrt_publish(f, 0, f->pass_name));
        vrt_prepare(f, &r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_ADMITTED, NULL));
        char argv_path[PATH_MAX];
        ASSERT(vrt_path(argv_path, f->work, ZCL_VERIFY_RECEIVER_ARGV));
        struct vr_bytes argv_bytes = {0};
        ASSERT(vrt_read(argv_path, &argv_bytes));
        argv_bytes.p[argv_bytes.n - 2u] ^= 1u;
        ASSERT(vrt_write(argv_path, argv_bytes.p, argv_bytes.n, 0600));
        free(argv_bytes.p);
        const struct vrt_zcc_env admitted = {.verified = true, .admitted = true};
        before = vrt_launches(f);
        ASSERT(vrt_zcc(f, '4', &admitted, out) == 0);
        ASSERT(vrt_launches(f) == before + 1u);
        zcl_verify_receiver_finish(&r);
        ASSERT(vrt_is(&r, ZCL_VERIFY_RECEIVER_COLD, "admitted_argv_mismatch"));
        ASSERT(r.compile_launches == 1u && r.launches_avoided == 0u);
        PASS();
    } _test_next:;
    zcl_verify_receiver_release(&r);
    return failures;
}

static void vrt_fixture_free(struct vrt_fx *f)
{
    zcl_verify_receiver_paths_free(f->inputs, f->input_count);
    free(f->obj.p);
    free(f->dep.p);
    free(f->err.p);
    (void)unsetenv(VRT_KEY_ENV);
    if (f->root[0]) (void)nftw(f->root, vrt_rm, 8, FTW_DEPTH | FTW_PHYS);
    if (f->key_root[0]) (void)nftw(f->key_root, vrt_rm, 8, FTW_DEPTH | FTW_PHYS);
    if (f->anchor[0]) (void)nftw(f->anchor, vrt_rm, 8, FTW_DEPTH | FTW_PHYS);
}

int test_verify_receiver(void)
{
    int failures = 0;
    struct vrt_fx *f = calloc(1, sizeof(*f));
    TEST("verify receiver: fixture world from a real verifier-shaped compile") {
        ASSERT(f != NULL);
        ASSERT(zcl_verify_attest_test_override_compiled());
        ASSERT(vrt_fixture_make(f));
        PASS();
    } _test_next:;
    if (!failures) failures += vrt_test_hit(f);
    if (!failures) failures += vrt_test_pin_equals_receiver(f);
    if (!failures) failures += vrt_test_cold_trust(f);
    if (!failures) failures += vrt_test_cold_record(f);
    if (!failures) failures += vrt_test_cold_source(f);
    if (!failures) failures += vrt_test_block(f);
    if (!failures) failures += vrt_test_depfile_admission(f);
    if (!failures) failures += vrt_test_depfile_after_make(f);
    if (!failures) failures += vrt_test_zcc_target_shape(f);
    if (!failures) failures += vrt_test_admitted_log(f);
    if (!failures) failures += vrt_test_zcc_other_tree(f);
    if (!failures) failures += vrt_test_planted(f);
    if (f) vrt_fixture_free(f);
    free(f);
    return failures;
}
#endif
