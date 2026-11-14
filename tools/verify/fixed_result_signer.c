/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: The fixed-result signer core: independent receipt and artifact
 *          checks, key v2 rebuilt from pins, one sealed record, private
 *          staging. See fixed_result_signer.h. */
#if defined(__linux__)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "verify/fixed_result_signer.h"

#include "base/cleanse.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/ed25519.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FRS_PROFILE_LINES ZCL_FR_PROFILE_ARGC
#define FRS_TAIL_MAX 12u
#define FRS_ARGV_MAX (FRS_PROFILE_LINES + FRS_TAIL_MAX)
#define FRS_RECEIPT_MAX (64u * 1024u)
#define FRS_OBJECT_MAX (8u * 1024u * 1024u)
#define FRS_OUTPUT_MAX (4u * 1024u * 1024u)
#define FRS_CWD_TAG "@CWD@"

static const char *const k_frs_env[] = {
    "LC_ALL=C", "TZ=UTC", "TMPDIR=/tmp", "PATH=/usr/bin:/bin"
};

static const char *const k_frs_input_names[ZCL_FRS_INPUTS] = {
    "launch.bin", "object.o", "deps.d", "stderr.bin", "preprocessed.i"
};

/* ── launch.bin ───────────────────────────────────────────────────────── */

const char *zcl_frs_launch_parse(const uint8_t *bytes, size_t len,
                                 struct zcl_frs_launch *out)
{
    const char *why = NULL;
    if (!out || !bytes) return ZCL_FRS_WHY_ARGUMENTS;
    memset(out, 0, sizeof(*out));
    if (zcl_fr_receipt_parse(bytes, len, &out->f.launch, &why)) {
        zcl_sha3_256(bytes, len, out->sha3);
        return NULL;
    }
    if (!why || strcmp(why, ZCL_FR_WHY_WRONG_ARTIFACT) != 0) return why;
    if (!zcl_fr_failure_parse(bytes, len, &out->f, &why)) return why;
    out->failure = true;
    zcl_sha3_256(bytes, len, out->sha3);
    return NULL;
}

/* ── exec argv v2, rederived from the pinned profile ──────────────────── */

struct frs_argv {
    char *lines;           /* NUL-separated copy of the profile */
    char cwd_line[8192];   /* the one line with @CWD@ expanded */
    char dep[64];
    char out[64];
    const char *argv[FRS_ARGV_MAX + 1u];
    size_t argc;
};

static bool frs_expand_cwd(struct frs_argv *a, const char *line)
{
    const char *tag = strstr(line, FRS_CWD_TAG);
    if (!tag || strstr(tag + 1, FRS_CWD_TAG)) return false;
    int n = snprintf(a->cwd_line, sizeof(a->cwd_line), "%.*s%s%s",
                     (int)(tag - line), line, ZCL_FR_CWD,
                     tag + sizeof(FRS_CWD_TAG) - 1u);
    return n > 0 && (size_t)n < sizeof(a->cwd_line);
}

/* The pinned profile lines with @CWD@ replaced by /zclassic23 exactly once,
 * as the worker's read_profile builds them. */
static bool frs_profile_argv(struct frs_argv *a, const uint8_t *profile,
                             size_t len)
{
    size_t tags = 0;
    if (len == 0 || profile[len - 1u] != '\n' || memchr(profile, 0, len))
        return false;
    a->lines = zcl_malloc(len, "frs profile lines");
    if (!a->lines) return false;
    memcpy(a->lines, profile, len);
    char *line = a->lines;
    for (size_t i = 0; i < len; i++) {
        if (a->lines[i] != '\n') continue;
        a->lines[i] = '\0';
        if (!*line || a->argc == FRS_PROFILE_LINES) return false;
        a->argv[a->argc] = line;
        if (strstr(line, FRS_CWD_TAG)) {
            if (tags++ != 0 || !frs_expand_cwd(a, line)) return false;
            a->argv[a->argc] = a->cwd_line;
        }
        a->argc++;
        line = a->lines + i + 1u;
    }
    return a->argc == FRS_PROFILE_LINES && tags == 1u &&
           strcmp(a->argv[0], "cc") == 0;
}

/* The worker's -c tail (deps.d, result.o) or its checker -E tail
 * (preprocess.d, -fno-working-directory, result.i), under `scratch`. */
static bool frs_tail(struct frs_argv *a, const struct zcl_fr_receipt *r,
                     bool preprocess)
{
    int d = snprintf(a->dep, sizeof(a->dep), "%s/%s", r->scratch,
                     preprocess ? "preprocess.d" : "deps.d");
    int o = snprintf(a->out, sizeof(a->out), "%s/%s", r->scratch,
                     preprocess ? "result.i" : "result.o");
    if (d <= 0 || (size_t)d >= sizeof(a->dep) || o <= 0 ||
        (size_t)o >= sizeof(a->out))
        return false;
    const char *tail[FRS_TAIL_MAX];
    size_t n = 0;
    tail[n++] = "-MMD"; tail[n++] = "-MP"; tail[n++] = "-MF";
    tail[n++] = a->dep; tail[n++] = "-MT"; tail[n++] = r->target;
    if (preprocess) tail[n++] = "-fno-working-directory";
    tail[n++] = preprocess ? "-E" : "-c";
    tail[n++] = "-o"; tail[n++] = a->out; tail[n++] = ZCL_FR_SOURCE;
    for (size_t i = 0; i < n; i++) a->argv[a->argc++] = tail[i];
    a->argv[a->argc] = NULL;
    return true;
}

static bool frs_argv_build(struct frs_argv *a, const struct zcl_frt_trust *t,
                           const struct zcl_fr_receipt *r, bool preprocess)
{
    memset(a, 0, sizeof(*a));
    return frs_profile_argv(a, t->profile, t->profile_len) &&
           frs_tail(a, r, preprocess);
}

static const char *frs_argv_hash(const struct zcl_frt_trust *t,
                                 const struct zcl_fr_receipt *r,
                                 bool preprocess, const uint8_t want[32])
{
    struct frs_argv a;
    uint8_t got[32];
    const char *why = ZCL_FRS_WHY_PROFILE;
    if (frs_argv_build(&a, t, r, preprocess))
        why = zcl_fr_exec_argv_sha3(a.argv, a.argc, got) &&
                      memcmp(got, want, 32u) == 0
                  ? NULL : ZCL_FRS_WHY_EXEC_ARGV;
    free(a.lines);
    return why;
}

static const char *frs_pins_equal(const struct zcl_fixed_result_v2_roots *a,
                                   const struct zcl_fixed_result_v2_roots *b)
{
    for (size_t i = 0; i < ZCL_FR_ROOT_COUNT; i++)
        if (memcmp(zcl_fr_root_at(a, i), zcl_fr_root_at(b, i), 32u) != 0)
            return ZCL_FR_WHY_PIN_MISMATCH;
    return NULL;
}

const char *zcl_frs_expected_rebuild(const struct zcl_frt_trust *trust,
                                     const struct zcl_frs_launch *launch,
                                     const uint8_t pp_sha3[32],
                                     struct zcl_fixed_result_v2_expected *out)
{
    if (!trust || !launch || !pp_sha3 || !out || !trust->profile)
        return ZCL_FRS_WHY_ARGUMENTS;
    const struct zcl_fr_receipt *r = &launch->f.launch;
    const char *why = frs_pins_equal(&r->pins, &trust->pins);
    if (!why)
        why = frs_argv_hash(trust, r, true, r->preprocess_argv_sha3);
    if (!why) why = frs_argv_hash(trust, r, false, r->compile_argv_sha3);
    if (why) return why;
    struct frs_argv a;
    if (!frs_argv_build(&a, trust, r, false)) {
        free(a.lines);
        return ZCL_FRS_WHY_PROFILE;
    }
    /* The signer's own inputs: the pinned portable source root, the
     * rehashed -E stream, the pinned profile and the fixed environment. */
    bool ok = zcl_fixed_result_expected_v2(
        &trust->pins, trust->pins.source_content, pp_sha3, r->target,
        trust->profile, trust->profile_len, ZCL_FR_CWD, a.argv, a.argc,
        k_frs_env, sizeof(k_frs_env) / sizeof(k_frs_env[0]), -1, out, &why);
    free(a.lines);
    return ok ? NULL : (why ? why : ZCL_FRS_WHY_PROFILE);
}

void zcl_frs_record(const struct zcl_frt_trust *trust,
                    const struct zcl_frs_launch *launch,
                    const struct zcl_fixed_result_v2_expected *expected,
                    struct zcl_verify_attest_record *out)
{
    const struct zcl_fr_receipt *r = &launch->f.launch;
    memset(out, 0, sizeof(*out));
    out->binding.contract = (struct zcl_verify_attest_text){
        ZCL_FR_CONTRACT, sizeof(ZCL_FR_CONTRACT) - 1u};
    memcpy(out->binding.profile_sha3, trust->pins.profile_args, 32u);
    out->binding.target = (struct zcl_verify_attest_text){
        r->target, strlen(r->target)};
    memcpy(out->binding.receipt_sha3, launch->sha3, 32u);
    out->toolchain_id = expected->expected.toolchain_id;
    out->argv_norm = expected->expected.argv_norm;
    out->recorded_cwd = expected->expected.recorded_cwd;
    memcpy(out->pp_sha3, expected->expected.pp_sha3, 32u);
    memcpy(out->closure_sha3, expected->expected.closure_sha3, 32u);
    /* A failure names no object and no depfile: their digests stay zero. */
    memcpy(out->obj_sha3, r->artifacts[0].sha3, 32u);
    memcpy(out->dep_sha3, r->artifacts[1].sha3, 32u);
    memcpy(out->stderr_sha3, r->artifacts[2].sha3, 32u);
    out->exit_code = (int32_t)launch->f.compile_exit;
}

/* ── inputs ───────────────────────────────────────────────────────────── */

const char *zcl_frs_inputs_open(int launch_dir, int fds[ZCL_FRS_INPUTS])
{
    const char *why = NULL;
    for (size_t i = 0; i < ZCL_FRS_INPUTS; i++) fds[i] = -1;
    for (size_t i = 0; i < ZCL_FRS_INPUTS && !why; i++) {
        fds[i] = openat(launch_dir, k_frs_input_names[i],
                        O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        bool optional = i == ZCL_FRS_IN_OBJECT || i == ZCL_FRS_IN_DEPS;
        if (fds[i] < 0 && !(optional && errno == ENOENT))
            why = i == ZCL_FRS_IN_RECEIPT ? ZCL_FRS_WHY_RECEIPT_UNSAFE
                                          : ZCL_FRS_WHY_ARTIFACT_UNSAFE;
    }
    if (why) zcl_frs_inputs_close(fds);
    return why;
}

void zcl_frs_inputs_close(int fds[ZCL_FRS_INPUTS])
{
    for (size_t i = 0; i < ZCL_FRS_INPUTS; i++) {
        if (fds[i] >= 0) (void)close(fds[i]);
        fds[i] = -1;
    }
}

struct frs_bytes {
    uint8_t *p;
    size_t n;
};

struct frs_work {
    struct frs_bytes in[ZCL_FRS_INPUTS];
    struct zcl_frs_launch launch;
    struct zcl_fixed_result_v2_expected expected;
    struct zcl_verify_attest_record record;
    uint8_t *sealed;
    size_t sealed_len;
};

static void frs_work_free(struct frs_work *w)
{
    for (size_t i = 0; i < ZCL_FRS_INPUTS; i++) free(w->in[i].p);
    free(w->sealed);
}

/* Owner first, so a receipt or artifact written by anyone but the root
 * launcher is named as such before any other custody fault. */
static const char *frs_read_input(int fd, uint32_t owner, uint32_t mode,
                                  size_t max, bool receipt,
                                  struct frs_bytes *out)
{
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0)
        return receipt ? ZCL_FRS_WHY_RECEIPT_UNSAFE : ZCL_FRS_WHY_ARTIFACT_UNSAFE;
    if (st.st_uid != owner)
        return receipt ? ZCL_FRS_WHY_RECEIPT_OWNER : ZCL_FRS_WHY_ARTIFACT_OWNER;
    const struct zcl_frt_custody custody = {owner, mode, max};
    const char *why = NULL;
    if (zcl_frt_read_fd(fd, &custody, &out->p, &out->n, &why)) return NULL;
    return receipt ? ZCL_FRS_WHY_RECEIPT_UNSAFE : ZCL_FRS_WHY_ARTIFACT_UNSAFE;
}

static bool frs_digest_is(const struct zcl_fr_artifact_digest *d,
                          const struct frs_bytes *b)
{
    uint8_t hash[32];
    zcl_sha3_256(b->p, b->n, hash);
    return d->size == (uint64_t)b->n && memcmp(hash, d->sha3, 32u) == 0;
}

/* The artifacts the launch names, read as root-owned files and rehashed.
 * A failure has no object or depfile, and none may be offered. */
static const char *frs_read_artifacts(const struct zcl_frt_trust *t,
                                      const int fds[ZCL_FRS_INPUTS],
                                      struct frs_work *w)
{
    static const size_t max[ZCL_FRS_INPUTS] = {
        0u, FRS_OBJECT_MAX, FRS_OUTPUT_MAX, FRS_OUTPUT_MAX, FRS_OUTPUT_MAX};
    const struct zcl_fr_receipt *r = &w->launch.f.launch;
    const char *why = NULL;
    for (size_t i = ZCL_FRS_IN_OBJECT; i < ZCL_FRS_INPUTS && !why; i++) {
        bool named = !w->launch.failure ||
                     (i != ZCL_FRS_IN_OBJECT && i != ZCL_FRS_IN_DEPS);
        if (!named) {
            if (fds[i] >= 0) why = ZCL_FRS_WHY_INPUTS;
            continue;
        }
        why = frs_read_input(fds[i], t->launcher_uid, 0u, max[i], false,
                             &w->in[i]);
        if (!why && !frs_digest_is(&r->artifacts[i - 1u], &w->in[i]))
            why = ZCL_FR_WHY_RECEIPT_ARTIFACT;
    }
    if (!why && !w->launch.failure)
        why = zcl_fr_depfile_target_check(w->in[ZCL_FRS_IN_DEPS].p,
                                          w->in[ZCL_FRS_IN_DEPS].n, r->target);
    return why;
}

static const char *frs_identity(const struct zcl_frt_trust *t,
                                bool allow_same_uid)
{
    if ((uint32_t)geteuid() != t->signer_uid) return ZCL_FRS_WHY_UID_MISMATCH;
    if (!allow_same_uid && (t->signer_uid == t->launcher_uid ||
                            t->signer_uid == t->publisher_uid))
        return ZCL_FRS_WHY_SAME_UID;
    return NULL;
}

/* Everything the signer checks before it touches its key. */
static const char *frs_verify(const struct zcl_frt_trust *t,
                              const int fds[ZCL_FRS_INPUTS],
                              bool allow_same_uid, struct frs_work *w)
{
    const char *why = frs_identity(t, allow_same_uid);
    if (!why)
        why = frs_read_input(fds[ZCL_FRS_IN_RECEIPT], t->launcher_uid, 0444u,
                             FRS_RECEIPT_MAX, true, &w->in[ZCL_FRS_IN_RECEIPT]);
    if (!why)
        why = zcl_frs_launch_parse(w->in[ZCL_FRS_IN_RECEIPT].p,
                                   w->in[ZCL_FRS_IN_RECEIPT].n, &w->launch);
    if (!why) why = frs_pins_equal(&w->launch.f.launch.pins, &t->pins);
    if (!why) why = frs_read_artifacts(t, fds, w);
    if (!why) {
        uint8_t pp[32];
        zcl_sha3_256(w->in[ZCL_FRS_IN_PP].p, w->in[ZCL_FRS_IN_PP].n, pp);
        why = zcl_frs_expected_rebuild(t, &w->launch, pp, &w->expected);
    }
    if (!why) zcl_frs_record(t, &w->launch, &w->expected, &w->record);
    return why;
}

/* ── key ──────────────────────────────────────────────────────────────── */

static const char *frs_key_stat(const struct stat *st, uint32_t signer_uid)
{
    if (!S_ISREG(st->st_mode) || st->st_uid != signer_uid ||
        st->st_nlink != 1)
        return ZCL_FRS_WHY_KEY_UNSAFE;
    if ((st->st_mode & 0077u) != 0) return ZCL_FRS_WHY_KEY_ACCESSIBLE;
    if (st->st_size != 32) return ZCL_FRS_WHY_KEY_MALFORMED;
    return NULL;
}

const char *zcl_frs_key_read(int key_dir, const char *name,
                             uint32_t signer_uid, uint8_t seed[32])
{
    int fd = openat(key_dir, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK |
                                       O_CLOEXEC);
    if (fd < 0)
        return errno == ENOENT ? ZCL_FRS_WHY_KEY_MISSING : ZCL_FRS_WHY_KEY_UNSAFE;
    struct stat st;
    const char *why = fstat(fd, &st) == 0 ? frs_key_stat(&st, signer_uid)
                                          : ZCL_FRS_WHY_KEY_UNSAFE;
    if (!why && pread(fd, seed, 32u, 0) != 32) why = ZCL_FRS_WHY_KEY_MALFORMED;
    (void)close(fd);
    if (why) memory_cleanse(seed, 32u);
    return why;
}

/* The seed must not be the per-box proof signer key (readable by the
 * account that runs candidate code) and must be the root-pinned key. */
static const char *frs_key_check(const struct zcl_frt_trust *t,
                                 const uint8_t seed[32])
{
    uint8_t pub[32], secret[32];
    ed25519_keypair(pub, secret, seed);
    memory_cleanse(secret, sizeof(secret));
    if (!t->box.known) return ZCL_VERIFY_ATTEST_WHY_BOX_KEY_UNKNOWN;
    if (t->box.present && memcmp(pub, t->box.pubkey, 32u) == 0)
        return ZCL_FRS_WHY_KEY_IS_BOX;
    if (memcmp(pub, t->verifier_pubkey, 32u) != 0)
        return ZCL_FRS_WHY_KEY_NOT_PINNED;
    return NULL;
}

static const char *frs_sign(const struct zcl_frt_trust *t, int key_dir,
                            const char *key_name, struct frs_work *w)
{
    uint8_t seed[32];
    const char *why = zcl_frs_key_read(key_dir, key_name, t->signer_uid, seed);
    if (!why) why = frs_key_check(t, seed);
    if (!why && !zcl_verify_attest_seal(&w->record, seed, &w->sealed,
                                        &w->sealed_len, &why) && !why)
        why = ZCL_FRS_WHY_ARGUMENTS;
    memory_cleanse(seed, sizeof(seed));
    return why;
}

/* ── staging ──────────────────────────────────────────────────────────── */

static bool frs_write_file(int dir, const char *name, const uint8_t *p,
                           size_t n)
{
    int fd = openat(dir, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                                   O_CLOEXEC, 0400);
    if (fd < 0) return false;
    size_t at = 0;
    while (at < n) {
        ssize_t k = write(fd, p + at, n - at);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) break;
        at += (size_t)k;
    }
    bool ok = at == n && fchmod(fd, 0400) == 0 && fsync(fd) == 0;
    return close(fd) == 0 && ok;
}

struct frs_stage_file {
    const char *name;
    const struct frs_bytes *bytes;
};

static size_t frs_stage_files(const struct frs_work *w,
                              const struct frs_bytes *attest,
                              struct frs_stage_file out[5])
{
    size_t n = 0;
    out[n++] = (struct frs_stage_file){"attest.bin", attest};
    out[n++] = (struct frs_stage_file){"launch.bin", &w->in[ZCL_FRS_IN_RECEIPT]};
    out[n++] = (struct frs_stage_file){"stderr.bin", &w->in[ZCL_FRS_IN_STDERR]};
    if (!w->launch.failure) {
        out[n++] = (struct frs_stage_file){"object.o", &w->in[ZCL_FRS_IN_OBJECT]};
        out[n++] = (struct frs_stage_file){"deps.d", &w->in[ZCL_FRS_IN_DEPS]};
    }
    return n;
}

static void frs_stage_discard(int parent, const char *tmp,
                              const struct frs_stage_file *files, size_t n)
{
    int dir = openat(parent, tmp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                      O_CLOEXEC);
    for (size_t i = 0; dir >= 0 && i < n; i++)
        (void)unlinkat(dir, files[i].name, 0);
    if (dir >= 0) (void)close(dir);
    (void)unlinkat(parent, tmp, AT_REMOVEDIR);
}

static const char *frs_stage_fill(int parent, const char *tmp,
                                  const struct frs_stage_file *files, size_t n)
{
    int dir = openat(parent, tmp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                      O_CLOEXEC);
    bool ok = dir >= 0;
    for (size_t i = 0; ok && i < n; i++)
        ok = frs_write_file(dir, files[i].name, files[i].bytes->p,
                            files[i].bytes->n);
    if (ok) ok = fsync(dir) == 0;
    if (dir >= 0 && close(dir) != 0) ok = false;
    return ok ? NULL : ZCL_FRS_WHY_STAGING_WRITE;
}

/* Build the observation in a private temporary directory, then publish it
 * to the staging name with a no-replace rename, so the publisher never
 * sees a partial staging directory under the record's name. */
static const char *frs_stage(int staging, const char *record_hex,
                             const struct frs_work *w)
{
    const struct frs_bytes attest = {w->sealed, w->sealed_len};
    struct frs_stage_file files[5];
    size_t n = frs_stage_files(w, &attest, files);
    char tmp[96];
    int k = snprintf(tmp, sizeof(tmp), ".tmp-%s-%ld", record_hex,
                     (long)getpid());
    if (k <= 0 || (size_t)k >= sizeof(tmp)) return ZCL_FRS_WHY_ARGUMENTS;
    if (mkdirat(staging, tmp, 0700) != 0) return ZCL_FRS_WHY_STAGING_UNSAFE;
    const char *why = frs_stage_fill(staging, tmp, files, n);
    if (!why && renameat2(staging, tmp, staging, record_hex,
                          RENAME_NOREPLACE) != 0)
        why = errno == EEXIST ? ZCL_FRS_WHY_STAGING_EXISTS
                              : ZCL_FRS_WHY_STAGING_WRITE;
    if (why) frs_stage_discard(staging, tmp, files, n);
    else if (fsync(staging) != 0) why = ZCL_FRS_WHY_STAGING_WRITE;
    return why;
}

static void frs_result(const struct frs_work *w, struct zcl_frs_result *out)
{
    uint8_t hash[32];
    zcl_sha3_256(w->sealed, w->sealed_len, hash);
    zcl_hex_encode(hash, sizeof(hash), out->record_sha3);
    const struct zcl_verify_attest_expected *e = &w->expected.expected;
    zcl_verify_attest_store_key_hex(&e->toolchain_id, &e->argv_norm,
                                    &e->recorded_cwd, e->pp_sha3,
                                    e->closure_sha3, out->store_key);
    out->failure = w->launch.failure;
    out->exit_code = w->record.exit_code;
}

void zcl_frs_seal(const struct zcl_frt_trust *trust,
                  const int inputs[ZCL_FRS_INPUTS], int key_dir,
                  const char *key_name, int staging, bool allow_same_uid,
                  struct zcl_frs_result *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!trust || !inputs || key_dir < 0 || !key_name || staging < 0) {
        out->reason = ZCL_FRS_WHY_ARGUMENTS;
        return;
    }
    struct frs_work *w = zcl_calloc(1u, sizeof(*w), "frs work");
    if (!w) { out->reason = ZCL_FRS_WHY_NO_MEMORY; return; }
    const char *why = frs_verify(trust, inputs, allow_same_uid, w);
    if (!why) why = frs_sign(trust, key_dir, key_name, w);
    if (!why) {
        frs_result(w, out);
        why = frs_stage(staging, out->record_sha3, w);
    }
    if (why) memset(out, 0, sizeof(*out));
    out->reason = why;
    frs_work_free(w);
    free(w);
}

/* ── production and fixture entry points ──────────────────────────────── */

/* /var/lib/z23verify below "/", then its signer-private child. */
static int frs_state_child(const char *child, uint32_t signer_uid,
                           const char **why)
{
    int root = zcl_frt_open_root(why);
    int state = root >= 0 ? zcl_frt_open_path(root, ZCL_FRT_STATE_DIR, 0u, why)
                          : -1;
    int dir = state >= 0 ? zcl_frt_open_dir(state, child, signer_uid, true, why)
                         : -1;
    if (state >= 0) (void)close(state);
    if (root >= 0) (void)close(root);
    return dir;
}

void zcl_frs_seal_production(const int inputs[ZCL_FRS_INPUTS],
                             struct zcl_frs_result *out)
{
    struct zcl_frt_trust trust;
    const char *why = NULL;
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if ((uint32_t)geteuid() != ZCL_FRT_SIGNER_UID) {
        out->reason = ZCL_FRS_WHY_UID_NOT_VERIFIER;
        return;
    }
    if (!zcl_frt_load_production(&trust, &why)) { out->reason = why; return; }
    int key_dir = frs_state_child(ZCL_FRS_KEY_DIR, trust.signer_uid, &why);
    int staging = key_dir >= 0 ? frs_state_child(ZCL_FRS_STAGING_DIR,
                                                 trust.signer_uid, &why) : -1;
    if (staging >= 0)
        zcl_frs_seal(&trust, inputs, key_dir, ZCL_FRS_KEY_NAME, staging,
                     false, out);
    else
        out->reason = why;
    if (staging >= 0) (void)close(staging);
    if (key_dir >= 0) (void)close(key_dir);
    zcl_frt_release(&trust);
}

const char *zcl_frs_pubkey_production(char hex[65])
{
    uint8_t seed[32], pub[32], secret[32];
    const char *why = NULL;
    if ((uint32_t)geteuid() != ZCL_FRT_SIGNER_UID)
        return ZCL_FRS_WHY_UID_NOT_VERIFIER;
    int key_dir = frs_state_child(ZCL_FRS_KEY_DIR, ZCL_FRT_SIGNER_UID, &why);
    if (key_dir < 0) return why;
    why = zcl_frs_key_read(key_dir, ZCL_FRS_KEY_NAME, ZCL_FRT_SIGNER_UID, seed);
    (void)close(key_dir);
    if (why) return why;
    ed25519_keypair(pub, secret, seed);
    memory_cleanse(secret, sizeof(secret));
    memory_cleanse(seed, sizeof(seed));
    zcl_hex_encode(pub, sizeof(pub), hex);
    return NULL;
}

#ifdef ZCL_TESTING
static int frs_fixture_dir(const char *path, uint32_t owner)
{
    int fd = path ? open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                   O_CLOEXEC) : -1;
    struct stat st;
    if (fd >= 0 && fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) &&
        st.st_uid == owner && (st.st_mode & 0077u) == 0)
        return fd;
    if (fd >= 0) (void)close(fd);
    return -1;
}

void zcl_frs_seal_fixture(const struct zcl_frs_fixture *fixture,
                          const int inputs[ZCL_FRS_INPUTS],
                          struct zcl_frs_result *out)
{
    struct zcl_frt_trust trust;
    const char *why = NULL;
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!fixture) { out->reason = ZCL_FRS_WHY_ARGUMENTS; return; }
    if (!zcl_frt_load_fixture(&fixture->trust, &trust, &why)) {
        out->reason = why;
        return;
    }
    /* Identity before any private directory is opened, as in production. */
    why = frs_identity(&trust, fixture->allow_same_uid);
    int key_dir = why ? -1 : frs_fixture_dir(fixture->key_dir,
                                             trust.signer_uid);
    int staging = why ? -1 : frs_fixture_dir(fixture->staging_dir,
                                             trust.signer_uid);
    if (key_dir >= 0 && staging >= 0)
        zcl_frs_seal(&trust, inputs, key_dir, ZCL_FRS_KEY_NAME, staging,
                     fixture->allow_same_uid, out);
    else
        out->reason = why ? why : key_dir < 0 ? ZCL_FRS_WHY_KEY_UNSAFE
                                              : ZCL_FRS_WHY_STAGING_UNSAFE;
    if (staging >= 0) (void)close(staging);
    if (key_dir >= 0) (void)close(key_dir);
    zcl_frt_release(&trust);
}
#endif

#else
/* The verifier scope is one Linux x86-64 translation unit. */
typedef int zcl_fixed_result_signer_linux_only;
#endif
