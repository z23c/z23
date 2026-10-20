/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_ops_release_sign - `ops release sign` (tools/command/
 * native_ops_release_sign.c): a dedicated fleet release key signs LANDED MAIN
 * only, with the ZRS1 hybrid.
 *
 *   a. a landed commit with a good manifest writes z23-<commit12>.v2.zid that
 *      verifies under the pair pin (`zcode release verify` with the package
 *      root, and `ops slot install` against a package store holding the same
 *      manifest), and the signed root equals an independently folded vcs
 *      package root over the listed files plus MANIFEST.sha256
 *   b. a commit not on origin/main (and an unknown one) is
 *      RELEASE_NOT_LANDED: no doc, no receipt
 *   c. a tampered binary, a missing file and a tampered MANIFEST.sha256 are
 *      RELEASE_MANIFEST_MISMATCH: nothing written
 *   d. an existing .zid is not overwritten (RELEASE_DOC_EXISTS)
 *   e. neither seed's hex appears in any reply field or on stderr, on a good
 *      run and on refusals
 *
 * Hermetic: per-pid ./test-tmp directory, a fixture git repo whose
 * refs/remotes/origin/main is set by hand, fixture seeds, no network.
 */

#include "test/test_core.h"

#include "command/native_command.h"

#include "crypto/sha256.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/spawn.h"
#include "vcs/package_content.h"
#include "vcs/package_manifest.h"
#include "vcs/package_store.h"
#include "zid/zid.h"
#include "zid/zid_hybrid.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ORT_BIG (VCS_PACKAGE_CHUNK_BYTES + 29u) /* two chunks */
#define ORT_SMALL 777u

struct ort_cmd {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

struct ort_fx {
    char dir[PATH_MAX], repo[PATH_MAX], rel[PATH_MAX], data[PATH_MAX];
    char slots[PATH_MAX], seed[PATH_MAX], pq_seed[PATH_MAX], log[PATH_MAX];
    char seed_hex[65], pq_seed_hex[ZRS1_PQ_SEED_SIZE * 2 + 1];
    char landed[41], side[41], pin_line[256], master_hex[65];
    uint8_t *big;
    uint8_t small[ORT_SMALL];
};

static void ort_init(struct ort_cmd *c, const char *schema)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, schema);
}

static void ort_free(struct ort_cmd *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool ort_ok(const struct ort_cmd *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED &&
           c->reply.exit_code == ZCL_COMMAND_EXIT_OK;
}

static bool ort_code(const struct ort_cmd *c, const char *code)
{
    return c->reply.status != ZCL_COMMAND_STATUS_PASSED &&
           strcmp(c->reply.error.code, code) == 0;
}

static const char *ort_str(const struct ort_cmd *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return (v && v->type == JSON_STR) ? json_get_str(v) : NULL;
}

static int ort_check(bool ok, const char *what)
{
    printf("ops_release_sign: %s... %s\n", what, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static bool ort_write(const char *path, const void *data, size_t len,
                      mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return false;
    bool ok = write(fd, data, len) == (ssize_t)len;
    close(fd);
    return ok && chmod(path, mode) == 0;
}

static bool ort_exists(const char *dir, const char *leaf)
{
    char path[PATH_MAX];
    struct stat st;
    snprintf(path, sizeof(path), "%s/%s", dir, leaf);
    return lstat(path, &st) == 0;
}

static size_t ort_count(const char *dir)
{
    DIR *d = opendir(dir);
    size_t n = 0;
    for (struct dirent *e; d && (e = readdir(d));)
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
            n++;
    if (d)
        closedir(d);
    return n;
}

static void ort_rm_tree(const char *path)
{
    DIR *d = opendir(path);
    if (!d) {
        (void)unlink(path);
        return;
    }
    for (struct dirent *e; (e = readdir(d));) {
        char child[PATH_MAX];
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        snprintf(child, sizeof(child), "%s/%s", path, e->d_name);
        struct stat st;
        if (lstat(child, &st) == 0 && S_ISDIR(st.st_mode))
            ort_rm_tree(child);
        else
            (void)unlink(child);
    }
    closedir(d);
    (void)rmdir(path);
}

/* git -C repo args...; stdout trimmed into out. */
static bool ort_git(const char *repo, const char *const args[], char *out,
                    size_t cap)
{
    const char *argv[16] = {"git", "-C", repo};
    size_t n = 3;
    for (size_t i = 0; args[i] && n < 15; i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    char scratch[256];
    if (!out) {
        out = scratch;
        cap = sizeof(scratch);
    }
    int rc = zcl_spawn_capture(argv, out, cap, 30000);
    size_t len = strlen(out);
    while (len > 0 && (out[len - 1] == '\n' || out[len - 1] == '\r'))
        out[--len] = '\0';
    return rc == 0;
}

/* A commit with identity and signing forced off for the fixture only. */
static bool ort_commit(const char *repo, const char *msg, char sha[41])
{
    const char *c[] = {"-c", "user.name=fixture", "-c",
                       "user.email=fixture@invalid", "-c",
                       "commit.gpgsign=false", "commit", "-q", "--allow-empty",
                       "-m", msg, NULL};
    const char *rev[] = {"rev-parse", "HEAD", NULL};
    return ort_git(repo, c, NULL, 0) && ort_git(repo, rev, sha, 64);
}

static bool ort_git_fixture(struct ort_fx *fx)
{
    const char *init[] = {"init", "-q", NULL};
    const char *co_side[] = {"checkout", "-q", "-b", "side", NULL};
    if (mkdir(fx->repo, 0755) != 0 || !ort_git(fx->repo, init, NULL, 0) ||
        !ort_commit(fx->repo, "landed", fx->landed))
        return false;
    const char *upd[] = {"update-ref", "refs/remotes/origin/main", fx->landed,
                         NULL};
    return ort_git(fx->repo, upd, NULL, 0) &&
           ort_git(fx->repo, co_side, NULL, 0) &&
           ort_commit(fx->repo, "not landed", fx->side) &&
           strcmp(fx->landed, fx->side) != 0;
}

static void ort_sha_hex(const void *data, size_t len, char hex[65])
{
    struct sha256_ctx ctx;
    uint8_t h[32];
    sha256_init(&ctx);
    sha256_write(&ctx, data, len);
    sha256_finalize(&ctx, h);
    HexStr(h, 32, false, hex, 65);
}

static bool ort_write_manifest(const struct ort_fx *fx)
{
    char a[65], b[65], text[512], path[PATH_MAX];
    ort_sha_hex(fx->big, ORT_BIG, a);
    ort_sha_hex(fx->small, ORT_SMALL, b);
    snprintf(text, sizeof(text), "%s  z23\n%s *z23-package-verify\n", a, b);
    snprintf(path, sizeof(path), "%s/MANIFEST.sha256", fx->rel);
    return ort_write(path, text, strlen(text), 0644);
}

/* The Ed25519 seed file, and the PQ seed file minted by the real keygen leaf. */
static bool ort_seeds(struct ort_fx *fx)
{
    char hex[64];
    uint8_t ed[32];
    memset(ed, 0x7C, sizeof(ed));
    HexStr(ed, 32, false, fx->seed_hex, sizeof(fx->seed_hex));
    memcpy(hex, fx->seed_hex, 64);
    bool ok = ort_write(fx->seed, hex, 64, 0600);
    struct ort_cmd k;
    ort_init(&k, "zcl.ops_release_sign_test.v1");
    json_push_kv_str(&k.input, "pq_seed_file", fx->pq_seed);
    zcl_native_handle_zcode_release_keygen_pq(&k.request, &k.reply);
    ok = ok && ort_ok(&k);
    ort_free(&k);
    int fd = open(fx->pq_seed, O_RDONLY);
    ssize_t n = fd >= 0 ? read(fd, fx->pq_seed_hex, ZRS1_PQ_SEED_SIZE * 2) : -1;
    if (fd >= 0)
        close(fd);
    return ok && n == (ssize_t)(ZRS1_PQ_SEED_SIZE * 2);
}

static bool ort_fixture(struct ort_fx *fx)
{
    char cwd[PATH_MAX], path[PATH_MAX];
    memset(fx, 0, sizeof(*fx));
    if (!getcwd(cwd, sizeof(cwd)))
        return false;
    snprintf(fx->dir, sizeof(fx->dir), "%s/test-tmp/%d_ors", cwd,
             (int)getpid());
    ort_rm_tree(fx->dir);
    (void)mkdir("./test-tmp", 0755);
    snprintf(fx->repo, sizeof(fx->repo), "%s/repo", fx->dir);
    snprintf(fx->rel, sizeof(fx->rel), "%s/rel", fx->dir);
    snprintf(fx->data, sizeof(fx->data), "%s/data", fx->dir);
    snprintf(fx->slots, sizeof(fx->slots), "%s/slots", fx->dir);
    snprintf(fx->seed, sizeof(fx->seed), "%s/ed.seed", fx->dir);
    snprintf(fx->pq_seed, sizeof(fx->pq_seed), "%s/pq.seed", fx->dir);
    snprintf(fx->log, sizeof(fx->log), "%s/stderr.log", fx->dir);
    if (mkdir(fx->dir, 0755) != 0 || mkdir(fx->rel, 0755) != 0 ||
        mkdir(fx->data, 0755) != 0 || !ort_git_fixture(fx))
        return false;
    setenv("ZCL_BINARY_SLOTS_DIR", fx->slots, 1);
    fx->big = malloc(ORT_BIG); // raw-alloc-ok:test-fixture
    if (!fx->big)
        return false;
    for (size_t i = 0; i < ORT_BIG; i++)
        fx->big[i] = (uint8_t)(0x31 + i * 7u);
    for (size_t i = 0; i < ORT_SMALL; i++)
        fx->small[i] = (uint8_t)(0x55 ^ i);
    snprintf(path, sizeof(path), "%s/z23", fx->rel);
    bool ok = ort_write(path, fx->big, ORT_BIG, 0755);
    snprintf(path, sizeof(path), "%s/z23-package-verify", fx->rel);
    ok = ok && ort_write(path, fx->small, ORT_SMALL, 0644) &&
         ort_write_manifest(fx);
    return ok && ort_seeds(fx);
}

/* Run ops.release.sign with stderr captured to fx->log. */
static void ort_run(const struct ort_fx *fx, const char *commit,
                    struct ort_cmd *c)
{
    ort_init(c, "zcl.ops_release_sign_test.v1");
    json_push_kv_str(&c->input, "release_dir", fx->rel);
    json_push_kv_str(&c->input, "commit", commit);
    json_push_kv_str(&c->input, "seed_file", fx->seed);
    json_push_kv_str(&c->input, "pq_seed_file", fx->pq_seed);
    json_push_kv_str(&c->input, "repo", fx->repo);
    json_push_kv_str(&c->input, "datadir", fx->data);
    fflush(stderr);
    int saved = dup(2);
    int fd = open(fx->log, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd >= 0) {
        dup2(fd, 2);
        close(fd);
    }
    zcl_native_handle_ops_release_sign(&c->request, &c->reply);
    fflush(stderr);
    if (saved >= 0) {
        dup2(saved, 2);
        close(saved);
    }
}

/* True iff neither seed appears in the reply (data and error) or the log. */
static bool ort_no_seed_leak(const struct ort_fx *fx, const struct ort_cmd *c)
{
    static char buf[1 << 16];
    size_t n = json_write(&c->reply.data, buf, sizeof(buf) - 512);
    snprintf(buf + n, 512, "|%s|%s|%s|%s", c->reply.error.code,
             c->reply.error.message, c->reply.error.evidence,
             c->reply.error.next_action);
    bool clean = !strstr(buf, fx->seed_hex) && !strstr(buf, fx->pq_seed_hex);
    FILE *f = fopen(fx->log, "r");
    char line[512];
    while (f && fgets(line, sizeof(line), f))
        if (strstr(line, fx->seed_hex) || strstr(line, fx->pq_seed_hex))
            clean = false;
    if (f)
        fclose(f);
    return clean;
}

/* The independent fold: vcs package root over the listed files plus the
 * manifest, built here with the content API (not the leaf's reader). */
static bool ort_expected_root(const struct ort_fx *fx, uint8_t root[32],
                              struct vcs_package_manifest *m)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/MANIFEST.sha256", fx->rel);
    int fd = open(path, O_RDONLY);
    char text[512];
    ssize_t n = fd >= 0 ? read(fd, text, sizeof(text)) : -1;
    if (fd >= 0)
        close(fd);
    vcs_package_manifest_init(m);
    return n > 0 &&
           vcs_package_content_add_file(m, "z23", VCS_PACKAGE_MODE_EXECUTABLE,
                                        fx->big, ORT_BIG) &&
           vcs_package_content_add_file(m, "z23-package-verify",
                                        VCS_PACKAGE_MODE_FILE, fx->small,
                                        ORT_SMALL) &&
           vcs_package_content_add_file(m, "MANIFEST.sha256",
                                        VCS_PACKAGE_MODE_FILE, (const uint8_t *)text,
                                        (size_t)n) &&
           vcs_package_manifest_root(m, root);
}

static bool ort_store_manifest(const struct ort_fx *fx,
                               struct vcs_package_manifest *m,
                               const uint8_t want_root[32])
{
    uint8_t *wire = NULL, root[32];
    size_t len = 0;
    bool ok = vcs_package_manifest_serialize(m, &wire, &len);
    struct vcs_package_store *store =
        ok ? vcs_package_store_open(fx->data, vcs_package_store_quota_bytes())
           : NULL;
    ok = store &&
         vcs_package_store_put_manifest(store, wire, len, root) ==
             VCS_PACKAGE_STORE_OK &&
         memcmp(root, want_root, 32) == 0 &&
         vcs_package_content_put_file(store, root, "z23", fx->big, ORT_BIG) ==
             VCS_PACKAGE_STORE_OK;
    if (store)
        vcs_package_store_close(store);
    free(wire);
    return ok;
}

static int ort_test_good(struct ort_fx *fx)
{
    struct ort_cmd c;
    int failures = 0;
    uint8_t root[32];
    char root_hex[65], doc_leaf[64], doc_path[PATH_MAX];
    struct vcs_package_manifest m;
    ort_run(fx, fx->landed, &c);
    failures += ort_check(ort_ok(&c), "a landed commit with a good manifest "
                          "signs");
    snprintf(doc_leaf, sizeof(doc_leaf), "z23-%.12s.v2.zid", fx->landed);
    snprintf(doc_path, sizeof(doc_path), "%s/%s", fx->rel, doc_leaf);
    struct stat st;
    failures += ort_check(lstat(doc_path, &st) == 0 &&
                              (st.st_mode & 0777u) == 0600u,
                          "the doc is <release_dir>/z23-<commit12>.v2.zid, "
                          "mode 0600");
    char rleaf[64];
    snprintf(rleaf, sizeof(rleaf), "release-sign-%.12s.receipt", fx->landed);
    failures += ort_check(ort_exists(fx->data, rleaf),
                          "a receipt row is sealed under the datadir");
    const char *pin = ort_str(&c, "pin_line");
    const char *got_root = ort_str(&c, "package_root");
    bool folded = ort_expected_root(fx, root, &m);
    HexStr(root, 32, false, root_hex, sizeof(root_hex));
    failures += ort_check(folded && got_root && strcmp(got_root, root_hex) == 0,
                          "the signed root is the independently folded vcs "
                          "package root over the listed files and "
                          "MANIFEST.sha256");
    failures += ort_check(ort_no_seed_leak(fx, &c),
                          "no seed bytes in the good reply or the log");
    if (pin)
        snprintf(fx->pin_line, sizeof(fx->pin_line), "%s", pin);
    const char *mk = ort_str(&c, "master_pubkey");
    if (mk)
        snprintf(fx->master_hex, sizeof(fx->master_hex), "%s", mk);
    ort_free(&c);

    /* zcode release verify under the pair pin and the package root. */
    struct ort_cmd v;
    ort_init(&v, "zcl.ops_release_sign_test.v1");
    json_push_kv_str(&v.input, "file", doc_path);
    json_push_kv_str(&v.input, "pin", fx->pin_line);
    json_push_kv_str(&v.input, "package_root", root_hex);
    json_push_kv_bool(&v.input, "require_pq", true);
    zcl_native_handle_zcode_release_verify(&v.request, &v.reply);
    failures += ort_check(ort_ok(&v), "zcode release verify accepts the doc "
                          "under the pair pin, root and require_pq");
    ort_free(&v);
    char ed_only[128];
    snprintf(ed_only, sizeof(ed_only), "%s", fx->master_hex);
    ort_init(&v, "zcl.ops_release_sign_test.v1");
    json_push_kv_str(&v.input, "file", doc_path);
    json_push_kv_str(&v.input, "pin", ed_only);
    zcl_native_handle_zcode_release_verify(&v.request, &v.reply);
    failures += ort_check(ort_code(&v, "RELEASE_PQ_UNPINNED"),
                          "an Ed25519-only pin never accepts the v2 doc");
    ort_free(&v);

    /* ops slot install against a store holding that manifest. */
    bool stored = folded && ort_store_manifest(fx, &m, root);
    vcs_package_manifest_free(&m);
    char from[PATH_MAX];
    snprintf(from, sizeof(from), "%s/z23", fx->rel);
    ort_init(&v, "zcl.ops_release_sign_test.v1");
    json_push_kv_str(&v.input, "release", doc_path);
    json_push_kv_str(&v.input, "from", from);
    json_push_kv_str(&v.input, "name", "ors-1");
    json_push_kv_str(&v.input, "package_root", root_hex);
    json_push_kv_str(&v.input, "datadir", fx->data);
    json_push_kv_str(&v.input, "pin", fx->pin_line);
    zcl_native_handle_ops_slot_install(&v.request, &v.reply);
    failures += ort_check(stored && ort_ok(&v), "ops slot install accepts the "
                          "doc under the pair pin against the same manifest");
    ort_free(&v);
    return failures;
}

static int ort_test_not_landed(struct ort_fx *fx)
{
    struct ort_cmd c;
    int failures = 0;
    size_t files_before = ort_count(fx->rel), data_before = ort_count(fx->data);
    ort_run(fx, fx->side, &c);
    failures += ort_check(ort_code(&c, "RELEASE_NOT_LANDED"),
                          "a commit not on origin/main is RELEASE_NOT_LANDED");
    char leaf[64];
    snprintf(leaf, sizeof(leaf), "z23-%.12s.v2.zid", fx->side);
    failures += ort_check(!ort_exists(fx->rel, leaf) &&
                              ort_count(fx->rel) == files_before &&
                              ort_count(fx->data) == data_before,
                          "a refused commit leaves no doc, no staging file "
                          "and no receipt");
    failures += ort_check(ort_no_seed_leak(fx, &c), "no seed bytes in the "
                          "not-landed refusal");
    ort_free(&c);
    ort_run(fx, "0123456789abcdef0123456789abcdef01234567", &c);
    failures += ort_check(ort_code(&c, "RELEASE_NOT_LANDED"),
                          "an unknown commit is RELEASE_NOT_LANDED too");
    ort_free(&c);
    ort_run(fx, "NOT-A-COMMIT", &c);
    failures += ort_check(ort_code(&c, "BAD_COMMIT"),
                          "a malformed commit is BAD_COMMIT");
    ort_free(&c);
    return failures;
}

static int ort_test_tamper(struct ort_fx *fx)
{
    struct ort_cmd c;
    int failures = 0;
    char path[PATH_MAX], leaf[64];
    snprintf(leaf, sizeof(leaf), "z23-%.12s.v2.zid", fx->landed);
    /* Fresh commit so the earlier good run's doc does not mask the check. */
    char other[41];
    const char *upd[] = {"update-ref", "refs/remotes/origin/main", NULL, NULL};
    const char *co[] = {"checkout", "-q", "-B", "tamper", fx->landed, NULL};
    if (!ort_git(fx->repo, co, NULL, 0) ||
        !ort_commit(fx->repo, "tamper base", other))
        return ort_check(false, "tamper fixture");
    upd[2] = other;
    if (!ort_git(fx->repo, upd, NULL, 0))
        return ort_check(false, "tamper fixture ref");
    snprintf(leaf, sizeof(leaf), "z23-%.12s.v2.zid", other);

    snprintf(path, sizeof(path), "%s/z23", fx->rel);
    fx->big[12345] ^= 0x40;
    ort_write(path, fx->big, ORT_BIG, 0755);
    size_t before = ort_count(fx->rel);
    ort_run(fx, other, &c);
    failures += ort_check(ort_code(&c, "RELEASE_MANIFEST_MISMATCH") &&
                              !ort_exists(fx->rel, leaf) &&
                              ort_count(fx->rel) == before,
                          "a tampered binary is RELEASE_MANIFEST_MISMATCH and "
                          "nothing is written");
    ort_free(&c);
    fx->big[12345] ^= 0x40;
    ort_write(path, fx->big, ORT_BIG, 0755);

    char moved[PATH_MAX];
    snprintf(moved, sizeof(moved), "%s/z23.gone", fx->rel);
    rename(path, moved);
    ort_run(fx, other, &c);
    failures += ort_check(ort_code(&c, "RELEASE_MANIFEST_MISMATCH") &&
                              !ort_exists(fx->rel, leaf),
                          "a listed file that is missing is "
                          "RELEASE_MANIFEST_MISMATCH");
    ort_free(&c);
    rename(moved, path);

    snprintf(path, sizeof(path), "%s/MANIFEST.sha256", fx->rel);
    ort_write(path, "garbage\n", 8, 0644);
    ort_run(fx, other, &c);
    failures += ort_check(ort_code(&c, "RELEASE_MANIFEST_MISMATCH") &&
                              !ort_exists(fx->rel, leaf),
                          "a malformed MANIFEST.sha256 is "
                          "RELEASE_MANIFEST_MISMATCH");
    ort_free(&c);
    ort_write_manifest(fx);

    ort_run(fx, other, &c);
    failures += ort_check(ort_ok(&c) && ort_exists(fx->rel, leaf),
                          "the repaired directory signs");
    ort_free(&c);
    return failures;
}

static int ort_test_no_overwrite(struct ort_fx *fx)
{
    struct ort_cmd c;
    int failures = 0;
    char path[PATH_MAX], before[8192], after[8192];
    snprintf(path, sizeof(path), "%s/z23-%.12s.v2.zid", fx->rel, fx->landed);
    int fd = open(path, O_RDONLY);
    ssize_t nb = fd >= 0 ? read(fd, before, sizeof(before)) : -1;
    if (fd >= 0)
        close(fd);
    size_t files = ort_count(fx->rel);
    ort_run(fx, fx->landed, &c);
    fd = open(path, O_RDONLY);
    ssize_t na = fd >= 0 ? read(fd, after, sizeof(after)) : -2;
    if (fd >= 0)
        close(fd);
    failures += ort_check(ort_code(&c, "RELEASE_DOC_EXISTS") && nb > 0 &&
                              nb == na && memcmp(before, after, (size_t)nb) == 0 &&
                              ort_count(fx->rel) == files,
                          "an existing .zid is refused and its bytes are "
                          "unchanged");
    failures += ort_check(ort_no_seed_leak(fx, &c), "no seed bytes in the "
                          "exists refusal");
    ort_free(&c);

    /* A foreign file squatting on the name is never replaced either. */
    char other[41];
    const char *upd[] = {"update-ref", "refs/remotes/origin/main", NULL, NULL};
    const char *co[] = {"checkout", "-q", "-B", "squat", fx->landed, NULL};
    if (!ort_git(fx->repo, co, NULL, 0) || !ort_commit(fx->repo, "squat", other))
        return failures + ort_check(false, "squat fixture");
    upd[2] = other;
    (void)ort_git(fx->repo, upd, NULL, 0);
    snprintf(path, sizeof(path), "%s/z23-%.12s.v2.zid", fx->rel, other);
    ort_write(path, "keep me\n", 8, 0600);
    ort_run(fx, other, &c);
    fd = open(path, O_RDONLY);
    char keep[16] = {0};
    if (fd >= 0) {
        if (read(fd, keep, sizeof(keep) - 1) < 0)
            keep[0] = 0;
        close(fd);
    }
    failures += ort_check(ort_code(&c, "RELEASE_DOC_EXISTS") &&
                              strcmp(keep, "keep me\n") == 0,
                          "a pre-existing file under the doc name survives");
    ort_free(&c);
    return failures;
}

int test_ops_release_sign(void)
{
    struct ort_fx fx;
    int failures = 0;
    printf("\n=== ops release sign tests ===\n");
    if (!ort_fixture(&fx)) {
        printf("ops_release_sign: fixture... FAIL\n");
        return 1;
    }
    failures += ort_test_good(&fx);
    failures += ort_test_not_landed(&fx);
    failures += ort_test_tamper(&fx);
    failures += ort_test_no_overwrite(&fx);
    free(fx.big);
    unsetenv("ZCL_BINARY_SLOTS_DIR");
    ort_rm_tree(fx.dir);
    printf("=== OPS_RELEASE_SIGN: %d failure(s) ===\n", failures);
    return failures;
}
