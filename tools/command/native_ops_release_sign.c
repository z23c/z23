/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: ops.release.sign - the fleet release signer. A dedicated release
 *          key signs LANDED MAIN ONLY: the leaf writes a ZRS1 v2 hybrid doc
 *          (Ed25519 + SLH-DSA-SHAKE-128s) beside a release's bytes, and only
 *          when every one of these holds:
 *            1. `commit` is 40 lowercase hex and an ancestor of the fetched
 *               origin/main of `repo` (RELEASE_NOT_LANDED);
 *            2. MANIFEST.sha256 in `release_dir` re-derives: every listed
 *               file is a plain file in that directory and its sha256 matches
 *               (RELEASE_MANIFEST_MISMATCH);
 *            3. <release_dir>/z23-<commit12>.v2.zid does not exist
 *               (RELEASE_DOC_EXISTS), and `datadir` exists for the receipt.
 *          Every refusal comes before any write, so a refused run leaves no
 *          doc, no staging file and no receipt.
 *
 * MANIFEST ROOT. The doc's manifest_root is the vcs package root
 * (vcs_package_manifest_root, zcl.package_manifest.v1) of the package whose
 * files are the ones MANIFEST.sha256 lists PLUS MANIFEST.sha256 itself, each
 * at its path, with mode 0100755 when any exec bit is set and 0100644
 * otherwise, and ordered 1 MiB SHA3-256 chunk hashes. It is exactly the
 * `package_root` that `ops slot install`, `zcode release verify
 * --package_root` and the pin gate compare against, and the manifest
 * `zcode package` stores for that root. Changing one byte of any listed file,
 * of MANIFEST.sha256, or a mode bit changes the root.
 *
 * VERSION. A release doc's version field is at most 32 printable characters
 * (a frozen wire field), so version is the first 32 hex characters of the
 * commit (128 bits); the file name and the receipt carry the first 12.
 *
 * SECRETS. Seeds come from 0600/0400 files only (the shared
 * zcl_zcode_release_sign_doc core), are wiped after use, and never reach argv,
 * the reply, a log or a receipt. The reply carries public keys only.
 */

#include "command/native_command.h"
#include "command/native_slot_common.h"
#include "command/native_zcode_release_sign.h"
#include "command/release_pin.h"

#include "encoding/utilstrencodings.h"
#include "base/safe_alloc.h"
#include "crypto/sha256.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"
#include "sha3/sha3.h"
#include "support/cleanse.h"
#include "util/path_util.h"
#include "vcs/package_manifest.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
static void ors_execute(const struct zcl_command_request *request,
                        struct zcl_command_reply *reply)
{
    (void)request;
    if (reply)
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "UNSUPPORTED_PLATFORM",
                               "normalize", false, false,
                               "release signing needs POSIX file semantics",
                               "ops.release.sign");
}
#else

#include "platform/private_file.h"
#include "util/authority_receipt.h"
#include "util/spawn.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#define ORS_CMD "ops.release.sign"
#define ORS_MANIFEST "MANIFEST.sha256"
#define ORS_MANIFEST_MAX 65536u
#define ORS_FILES_MAX 64u
#define ORS_GIT_MS 20000
#define ORS_SCHEMA "z23.release_sign.v1"
#define ORS_PATH_MAX 1100u

static void ors_fail(struct zcl_command_reply *reply, int exit_code,
                     const char *code, const char *phase, bool mutated,
                     const char *message, const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code, code,
                           phase, false, mutated, message, evidence);
    reply->error.human_action_required = true;
}

static bool ors_commit_ok(const char *c)
{
    if (!c || strlen(c) != 40u || !IsHex(c))
        return false;
    for (const char *p = c; *p; p++)
        if (*p >= 'A' && *p <= 'F')
            return false;
    return true;
}

/* ---- landed main -------------------------------------------------------- */

/* git -C <repo> <args...>; captured stdout, trailing newline stripped. The
 * exit status is not trusted (a reaped child can read as 0): callers judge
 * the captured text. */
static void ors_git(const char *repo, const char *const args[], char *out,
                    size_t cap)
{
    const char *argv[10];
    size_t n = 0;
    argv[n++] = "git";
    argv[n++] = "-C";
    argv[n++] = repo;
    for (size_t i = 0; args[i] && n + 1 < sizeof(argv) / sizeof(argv[0]); i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    out[0] = '\0';
    (void)zcl_spawn_capture(argv, out, cap, ORS_GIT_MS);
    size_t len = strlen(out);
    while (len > 0 && (out[len - 1] == '\n' || out[len - 1] == '\r'))
        out[--len] = '\0';
}

/* The tip of the fetched origin/main, then merge-base(commit, tip): the
 * commit is landed iff the merge base is the commit itself. */
static bool ors_landed(const char *repo, const char *commit,
                       struct zcl_command_reply *reply)
{
    char tip[128], base[128];
    const char *rev[] = {"rev-parse", "--verify", "--quiet",
                         "refs/remotes/origin/main", NULL};
    ors_git(repo, rev, tip, sizeof(tip));
    if (!ors_commit_ok(tip)) {
        ors_fail(reply, ZCL_COMMAND_EXIT_FAILED, "RELEASE_ORIGIN_UNKNOWN",
                 "execute", false,
                 "repo has no fetched origin/main; fetch it first "
                 "(git fetch origin main) and sign again", repo);
        return false;
    }
    const char *mb[] = {"merge-base", commit, tip, NULL};
    ors_git(repo, mb, base, sizeof(base));
    if (strcmp(base, commit) != 0) {
        ors_fail(reply, ZCL_COMMAND_EXIT_FAILED, "RELEASE_NOT_LANDED",
                 "execute", false,
                 "commit is not an ancestor of the fetched origin/main (or "
                 "is unknown to repo); a release key signs landed main only",
                 commit);
        return false;
    }
    return true;
}

/* ---- the manifest ------------------------------------------------------- */

struct ors_entry {
    uint8_t sha[32];
    char name[VCS_PACKAGE_PATH_SEGMENT_MAX + 1u];
};

static bool ors_mismatch(struct zcl_command_reply *reply, const char *why,
                         const char *name)
{
    ors_fail(reply, ZCL_COMMAND_EXIT_FAILED, "RELEASE_MANIFEST_MISMATCH",
             "execute", false, why, name);
    return false;
}

/* Read a whole small file through dirfd without following a symlink. */
static bool ors_read_small(int dirfd, const char *name, char *buf, size_t cap,
                           size_t *len)
{
    int fd = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
              st.st_size > 0 && (size_t)st.st_size < cap;
    ssize_t n = ok ? read(fd, buf, cap - 1u) : -1;
    close(fd);
    if (n != (ssize_t)st.st_size)
        return false;
    buf[n] = '\0';
    *len = (size_t)n;
    return true;
}

/* "<64 hex>  <name>" or "<64 hex> *<name>" lines, as sha256sum writes. */
static bool ors_parse(struct zcl_command_reply *reply, char *text,
                      struct ors_entry *ents, size_t *count)
{
    size_t n = 0;
    char *save = NULL;
    for (char *line = strtok_r(text, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        if (n == ORS_FILES_MAX)
            return ors_mismatch(reply, "MANIFEST.sha256 lists too many files",
                                ORS_MANIFEST);
        char hex[65];
        if (strlen(line) < 67u || line[64] != ' ' ||
            (line[65] != ' ' && line[65] != '*'))
            return ors_mismatch(reply, "MANIFEST.sha256 line is not "
                                "'<sha256>  <name>'", ORS_MANIFEST);
        memcpy(hex, line, 64u);
        hex[64] = '\0';
        const char *name = line + 66;
        if (!IsHex(hex) || ParseHex(hex, ents[n].sha, 32) != 32 ||
            strlen(name) > VCS_PACKAGE_PATH_SEGMENT_MAX ||
            strchr(name, '/') || !vcs_package_path_valid(name) ||
            strcmp(name, ORS_MANIFEST) == 0)
            return ors_mismatch(reply, "MANIFEST.sha256 line names a bad "
                                "digest or file name", ORS_MANIFEST);
        snprintf(ents[n].name, sizeof(ents[n].name), "%s", name);
        n++;
    }
    if (n == 0)
        return ors_mismatch(reply, "MANIFEST.sha256 lists no files",
                            ORS_MANIFEST);
    *count = n;
    return true;
}

/* One pass over an open file: sha256 and the ordered SHA3-256 chunk hashes.
 * False on a short read or when the file grew while it was read. */
static bool ors_hash_fd(int fd, uint64_t size, uint32_t chunks,
                        uint8_t *hashes, uint8_t sha[32])
{
    uint8_t *buf = zcl_malloc(VCS_PACKAGE_CHUNK_BYTES, "ors.chunk");
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    bool ok = buf != NULL;
    uint64_t done = 0;
    for (uint32_t i = 0; ok && i < chunks; i++) {
        size_t want_n = size - done > VCS_PACKAGE_CHUNK_BYTES
                            ? VCS_PACKAGE_CHUNK_BYTES : (size_t)(size - done);
        size_t got = 0;
        for (ssize_t r; got < want_n &&
                        (r = read(fd, buf + got, want_n - got)) > 0;)
            got += (size_t)r;
        ok = got == want_n;
        if (ok) {
            sha256_write(&ctx, buf, got);
            ok = vcs_package_chunk_hash(buf, got, hashes + (size_t)i * 32u);
        }
        done += got;
    }
    uint8_t probe;
    ok = ok && read(fd, &probe, 1) == 0; /* grew while read */
    sha256_finalize(&ctx, sha);
    free(buf);
    return ok;
}

/* A plain, not-too-large file opened without following a symlink, or -1. */
static int ors_open_plain(int dirfd, const char *name, struct stat *st)
{
    int fd = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd >= 0 && (fstat(fd, st) != 0 || !S_ISREG(st->st_mode) ||
                    (uint64_t)st->st_size > VCS_PACKAGE_MAX_FILE_BYTES)) {
        close(fd);
        fd = -1;
    }
    return fd;
}

/* Hash one listed file (checked against `want` when given) and enter it into
 * the package manifest. */
static bool ors_add_file(struct zcl_command_reply *reply, int dirfd,
                         const char *name, const uint8_t *want,
                         struct vcs_package_manifest *m)
{
    struct stat st;
    int fd = ors_open_plain(dirfd, name, &st);
    if (fd < 0)
        return ors_mismatch(reply, "a listed file is missing, is not a "
                            "plain file or is too large", name);
    uint64_t size = (uint64_t)st.st_size;
    uint32_t chunks = (uint32_t)((size + VCS_PACKAGE_CHUNK_BYTES - 1u) /
                                 VCS_PACKAGE_CHUNK_BYTES);
    uint8_t *hashes = chunks ? zcl_malloc((size_t)chunks * 32u, "ors.hashes")
                             : NULL;
    uint8_t sha[32];
    bool read_ok = (chunks == 0 || hashes) &&
                   ors_hash_fd(fd, size, chunks, hashes, sha);
    close(fd);
    bool match = read_ok && (!want || memcmp(sha, want, 32) == 0);
    uint32_t mode = (st.st_mode & 0111u) ? VCS_PACKAGE_MODE_EXECUTABLE
                                         : VCS_PACKAGE_MODE_FILE;
    bool added = match &&
                 vcs_package_manifest_add(m, name, mode, size, hashes, chunks);
    free(hashes);
    if (added)
        return true;
    return ors_mismatch(reply,
                        !read_ok ? "a listed file could not be read stably"
                        : !match ? "a listed file's sha256 differs from "
                                   "MANIFEST.sha256"
                                 : "a listed file cannot enter the package "
                                   "manifest (duplicate name or limits)",
                        name);
}

/* Re-derive MANIFEST.sha256 and fold the package root. */
static bool ors_root(struct zcl_command_reply *reply, const char *release_dir,
                     uint8_t root[32], size_t *files)
{
    int dirfd = open(release_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) {
        ors_fail(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_RELEASE_DIR",
                 "normalize", false,
                 "release_dir must be an existing directory", release_dir);
        return false;
    }
    char text[ORS_MANIFEST_MAX];
    size_t len = 0;
    struct ors_entry *ents = zcl_malloc(ORS_FILES_MAX * sizeof(*ents),
                                        "ors.entries");
    size_t count = 0;
    struct vcs_package_manifest m;
    vcs_package_manifest_init(&m);
    bool ok = ents != NULL;
    if (ok && !ors_read_small(dirfd, ORS_MANIFEST, text, sizeof(text), &len))
        ok = ors_mismatch(reply, "MANIFEST.sha256 is missing, empty, "
                          "oversize or not a plain file", release_dir);
    ok = ok && ors_parse(reply, text, ents, &count);
    for (size_t i = 0; ok && i < count; i++)
        ok = ors_add_file(reply, dirfd, ents[i].name, ents[i].sha, &m);
    ok = ok && ors_add_file(reply, dirfd, ORS_MANIFEST, NULL, &m);
    if (ok && !vcs_package_manifest_root(&m, root))
        ok = ors_mismatch(reply, "package root could not be derived",
                          release_dir);
    *files = count;
    vcs_package_manifest_free(&m);
    free(ents);
    close(dirfd);
    return ok;
}

/* ---- the doc ------------------------------------------------------------ */

/* Verify a saved doc through the same gate `zcode release verify` and
 * `ops slot install` use, under the pair pin and package_root a receiver
 * would hold, with require_pq. */
static bool ors_verify_saved(struct zcl_command_reply *reply,
                             const char *path, const char *pin_line,
                             const char *root_hex)
{
    struct release_pin_doc pd;
    const char *code = NULL;
    struct zid_release rel;
    memset(&rel, 0, sizeof(rel));
    if (!release_pin_read_any(path, &pd, &code)) {
        ors_fail(reply, ZCL_COMMAND_EXIT_FAILED, "RELEASE_VERIFY_FAILED",
                 "verify", false, "the saved doc could not be read back",
                 code ? code : path);
        return false;
    }
    struct json_value in;
    json_init(&in);
    json_set_object(&in);
    json_push_kv_str(&in, "pin", pin_line);
    json_push_kv_str(&in, "package_root", root_hex);
    json_push_kv_bool(&in, "require_pq", true);
    bool ok = pd.version == ZID_DOC_VERSION_V2 &&
              release_pin_doc_gate(&in, true, &pd,
                                   (uint64_t)platform_time_wall_unix(), &rel,
                                   reply, ORS_CMD) &&
              pd.pq_verified;
    json_free(&in);
    if (!ok && reply->status != ZCL_COMMAND_STATUS_FAILED)
        ors_fail(reply, ZCL_COMMAND_EXIT_FAILED, "RELEASE_VERIFY_FAILED",
                 "verify", false, "the saved doc is not a verified v2 doc",
                 path);
    return ok;
}

/* Exclusive private create + flush, then an atomic no-clobber publish. */
static int ors_publish(const char *dir, const char *final_path,
                       const char *hex)
{
    char staging[ORS_PATH_MAX + 16u];
    int n = snprintf(staging, sizeof(staging), "%s.staging", final_path);
    if (n <= 0 || (size_t)n >= sizeof(staging))
        return -1;
    struct platform_private_file file;
    platform_private_file_init(&file);
    size_t len = strlen(hex);
    bool ok = platform_private_file_create(staging, &file) &&
              platform_private_file_write_at(&file, hex, len, 0) &&
              platform_private_file_write_at(&file, "\n", 1, len) &&
              platform_private_file_authority_flush(&file);
    bool exists = false;
    ok = ok && platform_private_file_publish_no_clobber(&file, staging,
                                                        final_path, &exists);
    int rc = ok && !exists ? 0 : (exists ? 1 : -1);
    if (rc != 0)
        (void)platform_private_file_retire(&file, staging);
    platform_private_file_close(&file);
    if (rc == 0 && !platform_private_parent_flush(dir))
        rc = -2;
    return rc;
}

static bool ors_receipt(const char *datadir, const char *commit,
                        const uint8_t root[32], const uint8_t *wire,
                        size_t wire_len, char *name_out, size_t name_cap,
                        char *path_out, size_t path_cap)
{
    struct authority_receipt_header h;
    memset(&h, 0, sizeof(h));
    snprintf(h.schema, sizeof(h.schema), "%s", ORS_SCHEMA);
    memcpy(h.artifact_digest, root, 32);
    sha3_256((const unsigned char *)commit, 40u, h.context_anchor);
    sha3_256(wire, wire_len, h.detail_digest);
    int n = snprintf(name_out, name_cap, "release-sign-%.12s.receipt", commit);
    return n > 0 && (size_t)n < name_cap &&
           authority_receipt_header_seal_and_write(&h, datadir, name_out,
                                                   path_out, path_cap);
}

static bool ors_inputs(const struct zcl_command_request *request,
                       struct zcl_command_reply *reply, const char **dir,
                       const char **commit, const char **seed,
                       const char **pq_seed)
{
    const struct json_value *in = request->input;
    *dir = slot_json_str(in, "release_dir");
    *commit = slot_json_str(in, "commit");
    *seed = slot_json_str(in, "seed_file");
    *pq_seed = slot_json_str(in, "pq_seed_file");
    if (!*dir || !*commit || !*seed || !*pq_seed) {
        slot_refuse(reply, "MISSING_INPUT",
                    "ops release sign needs release_dir, commit (40 hex), "
                    "seed_file and pq_seed_file", ORS_CMD);
        return false;
    }
    if (!ors_commit_ok(*commit)) {
        slot_refuse(reply, "BAD_COMMIT",
                    "commit must be 40 lowercase hex characters", ORS_CMD);
        return false;
    }
    if (strlen(*dir) + 64u >= ORS_PATH_MAX) {
        slot_refuse(reply, "BAD_RELEASE_DIR", "release_dir path too long",
                    ORS_CMD);
        return false;
    }
    return true;
}

/* Everything the sign-and-write step needs, checked before the first write. */
struct ors_plan {
    const char *dir, *commit, *seed_file, *pq_seed_file, *datadir;
    uint8_t root[32];
    size_t files;
    int64_t seq, expiry;
};

/* The large buffers live on the heap, together, and are wiped as one. */
struct ors_job {
    struct zcode_release_signed sg;
    char doc_hex[ZID_DOC_V2_MAX * 2 + 1];
};

static void ors_sign_write(struct zcl_command_reply *reply,
                           struct ors_job *job, const struct ors_plan *p)
{
    struct zcode_release_signed *sg = &job->sg;
    char final_path[ORS_PATH_MAX], root_hex[65];
    int pn = snprintf(final_path, sizeof(final_path), "%s/z23-%.12s.v2.zid",
                      p->dir, p->commit);
    struct stat st;
    if (pn <= 0 || (size_t)pn >= sizeof(final_path) ||
        lstat(final_path, &st) == 0 || errno != ENOENT) {
        ors_fail(reply, ZCL_COMMAND_EXIT_FAILED, "RELEASE_DOC_EXISTS",
                 "execute", false,
                 "the release doc already exists (or cannot be checked); it "
                 "is never overwritten", final_path);
        return;
    }
    struct zid_release rel;
    memset(&rel, 0, sizeof(rel));
    snprintf(rel.name, sizeof(rel.name), "z23");
    snprintf(rel.version, sizeof(rel.version), "%.32s", p->commit);
    memcpy(rel.manifest_root, p->root, 32);
    if (!zcl_zcode_release_sign_doc(reply, &rel, (uint64_t)p->seq,
                                    (uint64_t)p->expiry, p->seed_file,
                                    p->pq_seed_file, sg))
        return;
    HexStr(p->root, 32, false, root_hex, sizeof(root_hex));
    char master_hex[65], pq_hex[ZRS1_PQ_PK_SIZE * 2 + 1], pin_line[256];
    HexStr(sg->master_pubkey, 32, false, master_hex, sizeof(master_hex));
    HexStr(sg->pq_pk, ZRS1_PQ_PK_SIZE, false, pq_hex, sizeof(pq_hex));
    snprintf(pin_line, sizeof(pin_line), "%s %s 0 %s", RELEASE_PIN_PAIR_TAG,
             master_hex, pq_hex);
    HexStr(sg->wire, sg->wire_len, false, job->doc_hex, sizeof(job->doc_hex));

    int rc = ors_publish(p->dir, final_path, job->doc_hex);
    if (rc != 0) {
        ors_fail(reply, ZCL_COMMAND_EXIT_FAILED,
                 rc == 1 ? "RELEASE_DOC_EXISTS" : "RELEASE_WRITE_FAILED",
                 "execute", rc == -2,
                 rc == 1 ? "the release doc already exists; it is never "
                           "overwritten"
                         : "the release doc could not be written; nothing "
                           "was published",
                 final_path);
        return;
    }
    if (!ors_verify_saved(reply, final_path, pin_line, root_hex)) {
        (void)unlink(final_path); /* ours: published just now, no-clobber */
        return;
    }
    char rname[96], rpath[ORS_PATH_MAX];
    if (!ors_receipt(p->datadir, p->commit, p->root, sg->wire, sg->wire_len,
                     rname, sizeof(rname), rpath, sizeof(rpath))) {
        ors_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "RECEIPT_FAILED",
                 "authorize", true,
                 "the doc was written and verified but its receipt could "
                 "not be persisted", final_path);
        return;
    }
    json_push_kv_str(&reply->data, "doc_path", final_path);
    json_push_kv_str(&reply->data, "receipt_path", rpath);
    json_push_kv_str(&reply->data, "commit", p->commit);
    json_push_kv_str(&reply->data, "name", rel.name);
    json_push_kv_str(&reply->data, "version", rel.version);
    json_push_kv_str(&reply->data, "package_root", root_hex);
    json_push_kv_int(&reply->data, "files", (int64_t)p->files);
    json_push_kv_str(&reply->data, "master_pubkey", master_hex);
    json_push_kv_str(&reply->data, "pq_pubkey", pq_hex);
    json_push_kv_str(&reply->data, "pin_line", pin_line);
    json_push_kv_int(&reply->data, "seq", p->seq);
    json_push_kv_int(&reply->data, "expiry", p->expiry);
    json_push_kv_int(&reply->data, "doc_bytes", (int64_t)sg->wire_len);
    json_push_kv_int(&reply->data, "doc_version", ZID_DOC_VERSION_V2);
    json_push_kv_bool(&reply->data, "verified", true);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

static void ors_execute(const struct zcl_command_request *request,
                        struct zcl_command_reply *reply)
{
    const struct json_value *in = request->input;
    struct ors_plan p;
    memset(&p, 0, sizeof(p));
    if (!ors_inputs(request, reply, &p.dir, &p.commit, &p.seed_file,
                    &p.pq_seed_file))
        return;
    const char *repo = slot_json_str(in, "repo");
    p.datadir = slot_json_str(in, "datadir");
    if (!repo)
        repo = ".";
    if (!p.datadir)
        p.datadir = zcl_native_command_datadir();
    int64_t now = platform_time_wall_unix();
    p.seq = json_get_int_or(in, "seq", now);
    p.expiry = json_get_int_or(in, "expiry", now + 365 * 86400);
    if (p.seq < 0 || p.expiry <= now) {
        slot_refuse(reply, "BAD_SEQ_OR_EXPIRY",
                    "seq must be >= 0 and expiry a future unix time", ORS_CMD);
        return;
    }
    if (!zcl_path_is_dir(p.datadir)) {
        slot_refuse(reply, "RELEASE_NO_DATADIR",
                    "the receipt needs an existing datadir (pass datadir)",
                    ORS_CMD);
        return;
    }
    /* Every refusal comes before the first write. */
    if (!ors_landed(repo, p.commit, reply) ||
        !ors_root(reply, p.dir, p.root, &p.files))
        return;
    struct ors_job *job = zcl_malloc(sizeof(*job), "ors.job");
    if (!job) {
        ors_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "OUT_OF_MEMORY", "execute",
                 false, "cannot allocate the signing buffers", ORS_CMD);
        return;
    }
    ors_sign_write(reply, job, &p);
    memory_cleanse(job, sizeof(*job));
    free(job);
}
#endif /* _WIN32 */

void zcl_native_handle_ops_release_sign(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    ors_execute(request, reply);
}
