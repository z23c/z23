/* Copyright 2026 Rhett Creighton - Apache 2.0 */
/*
 * Product acceptance contract for the resident-launch consumer.
 *
 * platform/resident_launch.h (9bc54830ad, "the launcher half of the app-run
 * path") is covered at the platform seam by test_resident_launch.c. The
 * consumer half is fleet peer C's production slice: the composition leaf
 * app.invoke.package (engine/composition/commands/apps.def →
 * tools/command/native_package_resident_command.c), its accepted-artifact
 * authority (contexts/commons/services/src/package_resident.c over the zcode
 * package lifecycle), its snapshot/launch owner
 * (contexts/commons/services/src/package_resident_launch.c), and the shipped
 * resident app contexts/commons/packages/ztasks. This group drives that REAL
 * product path end to end:
 *
 *   a. an accepted-artifact record (installed receipt → positioned-file
 *      triple + image SHA3) is produced by the production lifecycle and
 *      re-derived from product state at invocation time;
 *   b. a resident launch of that exact record verifies the mapped image;
 *   c. the child speaks z23-res-run-v1 frames on fd 3 (READY gate + one
 *      bounded input frame + one bounded result frame);
 *   d. the child's result is observable through the product reply;
 *   e. cancel/reap works (an unresponsive resident is refused inside the
 *      consumer's own bound and leaves no child behind);
 *   f. serving-generation supersession and atomic rollback — NOT WIRED
 *      in C's slice. Stage f is the independent acceptance TRAP for C's
 *      coming implementation (the fixed finish line, born-RED today):
 *      N serving as an authoritative product-state record → N+1 READY
 *      through the fd3 gate BEFORE any switch → atomic switch with no
 *      double-serving window → a late/stale N invocation refused → rapid
 *      N+2 supersession of a pending N+1 → forced-candidate-failure
 *      containment → EXACT-A rollback (same 64-hex digest) → restart
 *      persistence. Every trap check FAILS today naming the missing
 *      product behavior; the invocation contract it drives is the
 *      stage-f block of the ADAPTER SEAM below.
 *
 * Stage 0 is NOT the contract: it validates this file's reference child
 * fixture through the platform seam alone, speaking exactly the wire of C's
 * shipped ztasks child, so the bytes the consumer exchanges are proven
 * bytes, not guesses.
 */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "test/test_core.h"

#include "base/hex.h"
#include "config/command_catalog.h"
#include "core/uint256.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "platform/positioned_file.h"
#include "platform/resident_launch.h"
#include "services/package_lifecycle.h"
#include "services/package_resident.h"
#include "services/task_update.h"
#include "services/task_list.h"
#include "presentation/model_render.h"
#include "../../../contexts/explorer/modules/presentation/src/presentation_focus_internal.h"
#include "platform/os_proc.h"
#include "platform/os_sandbox.h"
#include "platform/time_compat.h"
#if !defined(_WIN32)
#include <sched.h>
#endif
#include "sha3/sha3.h"
#include "vcs/package_build.h"
#include "vcs/package_manifest.h"
#include "vcs/package_recipe.h"
#include "vcs/package_release.h"

#include <errno.h>
#include <fcntl.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#if !defined(_WIN32)
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

/* ── THE ADAPTER SEAM ─────────────────────────────────────────────────────
 * RLC_LEAF is the ONE name this contract depends on: the composition command
 * leaf that is the product consumer of platform/resident_launch.h. Per fleet
 * agreement 2026-09-14 (C mail 397/399, A ACK 400) the consumer is
 * app.invoke.package, owned by C, and it LANDED in this integration lane
 * (C patch 277ee6a3…, grant fix e7cf550e…). If the consumer ever moves,
 * change THIS ONE CONSTANT — no other product name is hardcoded here.
 *
 * The invocation contract is C's CONCRETE schema (renegotiated here per the
 * fleet agreement, replacing this file's original placeholder keys):
 *   input keys:  datadir (string: the zcode lifecycle datadir that owns the
 *                installed receipt), package_root (string, 64 lower-hex),
 *                receipt_id (string, 64 lower-hex: the exact installed build
 *                receipt), artifact_sha3 (string, 64 lower-hex: the receipt
 *                output digest the operator explicitly accepts), program
 *                (string: the exact install-relative receipt output, must be
 *                under bin/), input_text (string, ≤1024: the one bounded
 *                command frame), accept_execution (JSON boolean true — a
 *                string/number is refused by the registry's leaf-scoped bool
 *                rule; building or installing never grants execution).
 *   child side:  the launch nonce reaches the child as argv[2]
 *                (`<snapshot> --resident <nonce>`, empty environment); the
 *                child answers one READY frame, reads one z23-res-run-v1
 *                input frame, and answers one z23-res-run-v1 result frame on
 *                fd 3 (RESIDENT_LAUNCH_CHILD_FD).
 *   reply data:  artifact_sha3, program, result (the child's payload),
 *                mapped_proof, nonce, pid, start_token, verification_us,
 *                first_result_us, completed_us, child_reaped, next_action.
 *                Failure replies carry NO data.pid: the bounded invocation
 *                cancels and reaps BEFORE replying, so stage e proves the
 *                reap process-level (no waitable child remains), never from
 *                a reply field.
 *   semantics:   ONE bounded invocation — verify, snapshot, spawn, READY,
 *                one frame in, one frame out, cancel/reap. There is no
 *                long-lived resident and no product-held accepted-version
 *                record: every invocation names its exact receipt. Rollback
 *                today is the OPERATOR explicitly invoking a prior accepted
 *                receipt (next_action says so); serving-generation
 *                supersession and atomic rollback are NOT WIRED (stage f).
 *
 *   stage f serving-generation contract — THE FIXED FINISH LINE C codes
 *   against (NOT implemented today; every trap check in rlc_stage_f_trap
 *   is born-RED naming the missing piece). Deliberately small: no new
 *   lifecycle, no new state machine — ONE small serving record.
 *   serving record: per (datadir, app) the consumer owns one product-state
 *     record {package_root, receipt_id, artifact_sha3, program,
 *     generation}: the authoritative serving generation. The zcode
 *     lifecycle remains the install authority; this record only names
 *     which installed receipt currently SERVES.
 *   input keys (serving mode; the one-shot keys above still apply where
 *     an action binds exact bytes):
 *     app (string "publisher/package": the serving identity),
 *     action (string):
 *       "invoke"   (default; run the serving record — no receipt keys),
 *       "accept"   (admit the named receipt as the pending candidate:
 *                  verify + snapshot + spawn + nonce-bound READY + one
 *                  bounded probe frame through the fd3 gate BEFORE any
 *                  switch; serving is untouched; a second accept retires
 *                  the first pending candidate, cancelling and reaping
 *                  it),
 *       "activate" (atomically switch serving to the pending candidate
 *                  after re-proving it through the same gate; exactly one
 *                  serving generation exists at every instant — no
 *                  double-serving window),
 *       "rollback" (restore the exact prior accepted generation: same
 *                  64-hex artifact digest, never equivalent bytes, never
 *                  a pathname).
 *   reply data (serving mode adds): generation (int), serving_sha3,
 *     serving_receipt_id; accept adds pending_sha3, pending_receipt_id,
 *     candidate_nonce, candidate_start_token (the staleness binding) and
 *     superseded_sha3 (when a pending candidate was retired); activate
 *     adds switched_from_sha3.
 *   staleness: a result or invocation bound to a superseded generation
 *     (nonce + start_token + generation) is refused by name and cannot
 *     regain authority after a switch.
 *   failure evidence: a refused activation, a stale-generation refusal,
 *     or a failed serving invocation names the still-accepted serving
 *     64-hex digest in error.evidence.
 *   persistence: the record lives in product state (the datadir), never
 *     in process memory — after a consumer restart the same authoritative
 *     generation must still serve. */
#define RLC_LEAF "app.invoke.package"

#define RLC_CHECK(name, expr) do {                                        \
    printf("resident_launch_contract: %s... ", (name));                   \
    fflush(stdout);                                                       \
    if (expr) printf("OK\n");                                             \
    else { printf("FAIL\n"); failures++; }                                \
} while (0)

/* The one root-cause line printed when every stage fails for the same
 * reason: the product consumer does not exist in this tree. */
static void rlc_explain_absent(void)
{
    printf("resident_launch_contract: MISSING PRODUCT CONSUMER — no "
           "composition leaf '" RLC_LEAF "' is registered in the command "
           "catalog, so resident_launch has no product path: stages a–f "
           "above name the acceptance contract the consumer must satisfy "
           "(see the ADAPTER SEAM block in "
           "tests/harness/src/test_resident_launch_contract.c)\n");
}

/* False (and one named FAIL line) when the consumer leaf is absent, so a
 * blocked stage still reports which contract stage is unproven. */
static bool rlc_have_leaf(const struct zcl_command_spec *spec,
                          const char *stage)
{
    if (spec && spec->handler) return true;
    printf("resident_launch_contract: stage %s... FAIL (blocked: consumer "
           "leaf '" RLC_LEAF "' absent from the composition catalog)\n",
           stage);
    return false;
}

/* ── one in-process leaf invocation (the test_dev_orient idiom) ────────── */

struct rlc_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void rlc_begin(struct rlc_call *c, const struct zcl_command_spec *spec)
{
    memset(c, 0, sizeof(*c));
    json_set_object(&c->input);
    c->request.input = &c->input;
    c->request.spec = spec;
    zcl_command_reply_init(&c->reply, "zcl.package_resident.v1");
}

/* Crosses the REAL registry validator first: an input key the leaf never
 * declared fails here with the leaf's own reason, not in a shell later. */
static bool rlc_invoke(struct rlc_call *c)
{
    char why[192];
    if (!zcl_command_registry_input_validate(c->request.spec, &c->input,
                                             why, sizeof(why))) {
        printf("[contract input rejected by the leaf's own validator: %s] ",
               why);
        return false;
    }
    c->request.spec->handler(&c->request, &c->reply);
    return true;
}

static void rlc_end(struct rlc_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool rlc_ok(const struct rlc_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

/* ── stage a: production accepted-artifact producer ────────────────────── */

static int rlc_stage_a(const struct zcl_command_spec *spec)
{
    int failures = 0;
    RLC_CHECK("stage a: production accepted-artifact producer — leaf '"
              RLC_LEAF "' registered with a native handler",
              spec && spec->handler);
    return failures;
}

#if !defined(_WIN32)

static const char *rlc_str(const struct rlc_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

static long long rlc_int(const struct rlc_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_INT ? (long long)json_get_int(v) : -1;
}

static bool rlc_bool(const struct rlc_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

static bool rlc_hex64(const char *s)
{
    if (strlen(s) != 64) return false;
    for (size_t i = 0; i < 64; i++) {
        char ch = s[i];
        if ((ch < '0' || ch > '9') && (ch < 'a' || ch > 'f')) return false;
    }
    return true;
}

/* ── reference fixtures ─────────────────────────────────────────────────── */

/* The reference children are REAL ELF images built by the Makefile from
 * tests/harness/fixtures/resident_launch_contract_child.c and carried as
 * order-only prerequisites of every test binary, so a missing image is a
 * broken build, never a skip. A script cannot be the resident image: the
 * pinned descriptor is O_CLOEXEC, and fexecve of a shebang script re-opens
 * /dev/fd/N for the interpreter AFTER exec closed it (ENOENT on Linux).
 * rlc_child_v1 speaks exactly the landed consumer's wire (nonce as argv[2],
 * READY, one run frame round-trip; argv[3] "park" parks forever as the
 * cancel target); rlc_child_broken exits 1 without framing — the candidate
 * the READY gate must refuse. Paths are relative to the repository root,
 * the runner's cwd (the RB_SO_A idiom in test_hotswap_rollback.c). */
#define RLC_FIXTURE_CHILD "build/fixtures/rlc_child_v1"
#define RLC_FIXTURE_BROKEN "build/fixtures/rlc_child_broken"

static bool rlc_executable(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && (st.st_mode & 0111) != 0;
}

/* Capture the acceptance record for a file as it stands right now (the
 * test_resident_launch.c idiom: positioned-file triple + SHA3 through the
 * handle). */
static bool rlc_accept_of(const char *path, struct resident_launch_accepted *a)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot snap;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_snapshot(&file, &snap)) {
        platform_positioned_file_close(&file);
        return false;
    }
    unsigned char digest[32];
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    unsigned char chunk[4096];
    uint64_t offset = 0;
    for (;;) {
        int64_t got = platform_positioned_file_read(&file, chunk,
                                                    sizeof(chunk), offset);
        if (got < 0) { platform_positioned_file_close(&file); return false; }
        if (got == 0) break;
        sha3_256_write(&ctx, chunk, (size_t)got);
        offset += (uint64_t)got;
    }
    sha3_256_finalize(&ctx, digest);
    platform_positioned_file_close(&file);
    zcl_hex_encode(digest, sizeof(digest), a->image_sha3_hex);
    a->image_volume = snap.volume;
    a->image_low = snap.file_low;
    a->image_high = snap.file_high;
    a->image_size = snap.size;
    return true;
}

static bool rlc_wait_reaped(uint64_t pid)
{
    return waitpid((pid_t)pid, NULL, WNOHANG) == -1 && errno == ECHILD;
}

/* No child of this process remains, alive or zombie: the process-level reap
 * proof for the consumer's bounded invocation (failure replies carry no
 * data.pid by design — see the ADAPTER SEAM). */
static bool rlc_no_children(void)
{
    return waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD;
}

/* Parent-side write of one z23-res-run-v1 frame, mirroring the consumer's
 * npr_exchange (header + payload, nonce-bound). */
static bool rlc_send_frame(struct resident_launch *launch, const char *text)
{
    struct resident_result_header header;
    memset(&header, 0, sizeof(header));
    (void)snprintf(header.magic, sizeof(header.magic), "%s", "z23-res-run-v1");
    (void)snprintf(header.nonce, sizeof(header.nonce), "%s", launch->nonce);
    header.payload_len = (uint32_t)strlen(text);
    int fd = (int)launch->ipc_native;
    const unsigned char *parts[2] = { (const unsigned char *)&header,
                                      (const unsigned char *)text };
    size_t sizes[2] = { sizeof(header), header.payload_len };
    for (size_t p = 0; p < 2; p++) {
        for (size_t done = 0; done < sizes[p];) {
            ssize_t n = write(fd, parts[p] + done, sizes[p] - done);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) return false;
            done += (size_t)n;
        }
    }
    return true;
}

/* ── the smallest real installed package fixtures ─────────────────────────
 * The consumer binds ONLY an exact installed receipt: the artifact digest
 * comes from the verified install receipt, never from whichever bytes occupy
 * a pathname. So the contract installs REAL packages through the production
 * zcode lifecycle (publish → plan → commit), exactly like test_zcode_add.c:
 *   - ztasks, C's shipped resident app, from its REAL bytes under
 *     contexts/commons/packages/ztasks/ (the same package C's Mac factory
 *     run installed; tarball sha256 304a984e… matches the patch bytes);
 *   - rlc/parker, a minimal resident program that answers READY then parks
 *     forever — the unresponsive candidate stage e must see refused inside
 *     the consumer's own bound with nothing left behind.
 * The e2e lane forks build/bin/zclassic23-package-verify-dev — it MUST
 * exist; a missing binary is a loud failure, never a silent skip. */

#define RLC_ZTASKS_DIR "contexts/commons/packages/ztasks"
#define RLC_ZTASKS_PROGRAM "bin/ztasks"
#define RLC_PARKER_PROGRAM "bin/parker"

static bool rlc_mkdir_p(const char *path)
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
        if (mkdir(buf, 0700) != 0 && errno != EEXIST)
            return false;
        *p = '/';
    }
    return mkdir(buf, 0700) == 0 || errno == EEXIST;
}

static bool rlc_write_file(const char *path, const void *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = len == 0 || fwrite(data, 1, len, f) == len;
    if (fclose(f) != 0)
        ok = false;
    if (ok && chmod(path, 0600) != 0)
        ok = false;
    return ok;
}

static char *rlc_slurp(const char *path, size_t *len_out)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long size = ftell(f);
    if (size < 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)size + 1u);
    if (!buf) { fclose(f); return NULL; }
    bool ok = size == 0 || fread(buf, 1, (size_t)size, f) == (size_t)size;
    if (fclose(f) != 0) ok = false;
    if (!ok) { free(buf); return NULL; }
    buf[size] = '\0';
    *len_out = (size_t)size;
    return buf;
}

struct rlc_file {
    const char *path;
    const char *content;
    size_t len;
};

/* Publish one package (manifest + CAS chunks + recipe + signed release)
 * into <datadir>/zcode — the za_publish_ex idiom of test_zcode_add.c. */
static bool rlc_publish(const char *zcode, const char *name,
                        const char *semver, uint64_t sequence,
                        const struct rlc_file *files, size_t file_count,
                        const char *header_path, const char *source_path,
                        const char *test_path, const char *include_dir,
                        const char *program_path, uint8_t root_out[32])
{
    char dir[4400];
    const char *subs[] = { "manifests", "releases", "recipes", "cas/sha3" };
    for (size_t i = 0; i < 4; i++) {
        (void)snprintf(dir, sizeof(dir), "%s/%s", zcode, subs[i]);
        if (!rlc_mkdir_p(dir))
            return false;
    }

    struct vcs_package_manifest m;
    vcs_package_manifest_init(&m);
    bool ok = true;
    for (size_t i = 0; i < file_count && ok; i++) {
        uint8_t hash[32];
        struct sha3_256_ctx c;
        sha3_256_init(&c);
        sha3_256_write(&c, (const uint8_t *)files[i].content, files[i].len);
        sha3_256_finalize(&c, hash);
        ok = vcs_package_manifest_add(&m, files[i].path,
                                      VCS_PACKAGE_MODE_FILE, files[i].len,
                                      hash, 1);
        if (ok) {
            char hex[65];
            zcl_hex_encode(hash, 32, hex);
            char cdir[4400];
            char cpath[4500];
            (void)snprintf(cdir, sizeof(cdir), "%s/cas/sha3/%.2s", zcode, hex);
            (void)snprintf(cpath, sizeof(cpath), "%s/%s", cdir, hex);
            ok = rlc_mkdir_p(cdir) &&
                 rlc_write_file(cpath, files[i].content, files[i].len);
        }
    }
    if (ok)
        ok = vcs_package_manifest_root(&m, root_out);
    uint8_t *mwire = NULL;
    size_t mlen = 0;
    if (ok)
        ok = vcs_package_manifest_serialize(&m, &mwire, &mlen);
    vcs_package_manifest_free(&m);
    if (!ok)
        return false;
    char root_hex[65];
    zcl_hex_encode(root_out, 32, root_hex);
    char path[4500];
    (void)snprintf(path, sizeof(path), "%s/manifests/%s", zcode, root_hex);
    ok = rlc_write_file(path, mwire, mlen);
    free(mwire);
    if (!ok)
        return false;

    struct vcs_package_recipe r;
    vcs_package_recipe_init(&r);
    ok = vcs_package_recipe_add_header(&r, header_path, NULL);
    for (size_t i = 0; i < file_count && ok; i++) {
        size_t path_len = strlen(files[i].path);
        if (strcmp(files[i].path, header_path) != 0 && path_len > 2u &&
            strcmp(files[i].path + path_len - 2u, ".h") == 0)
            ok = vcs_package_recipe_add_header(&r, files[i].path, NULL);
    }
    ok = ok &&
         vcs_package_recipe_add_source(&r, source_path, NULL) &&
         vcs_package_recipe_add_test_source(&r, test_path, NULL) &&
         vcs_package_recipe_add_include_dir(&r, include_dir, NULL) &&
         vcs_package_recipe_add_library(&r, VCS_PACKAGE_RECIPE_LIB_LIBC,
                                        NULL) &&
         (!program_path ||
          vcs_package_recipe_add_program(&r, program_path, NULL));
    vcs_package_recipe_set_test_limits(&r, 0, 60,
                                       UINT64_C(64) * 1024u * 1024u);
    uint8_t recipe_root[32];
    uint8_t *rwire = NULL;
    size_t rlen = 0;
    if (ok)
        ok = vcs_package_recipe_root(&r, recipe_root) ==
                 VCS_PACKAGE_RECIPE_OK &&
             vcs_package_recipe_serialize(&r, &rwire, &rlen) ==
                 VCS_PACKAGE_RECIPE_OK;
    vcs_package_recipe_free(&r);
    if (!ok)
        return false;
    char rhex[65];
    zcl_hex_encode(recipe_root, 32, rhex);
    (void)snprintf(path, sizeof(path), "%s/recipes/%s", zcode, rhex);
    ok = rlc_write_file(path, rwire, rlen);
    free(rwire);
    if (!ok)
        return false;

    struct privkey sk;
    struct pubkey pk;
    memset(sk.vch, 0x11, 32);
    sk.fValid = true;
    sk.fCompressed = true;
    if (!privkey_get_pubkey(&sk, &pk))
        return false;
    struct vcs_package_release rel;
    memset(&rel, 0, sizeof(rel));
    rel.schema_version = VCS_PACKAGE_RELEASE_VERSION;
    (void)snprintf(rel.name, sizeof(rel.name), "%s", name);
    (void)snprintf(rel.semver, sizeof(rel.semver), "%s", semver);
    memcpy(rel.package_root, root_out, 32);
    memcpy(rel.publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    rel.publisher_sequence = sequence;
    (void)snprintf(rel.reward_address, sizeof(rel.reward_address), "t1fixture");
    (void)snprintf(rel.license, sizeof(rel.license), "Apache-2.0");
    memcpy(rel.recipe_root, recipe_root, 32);
    (void)snprintf(rel.chain_id, sizeof(rel.chain_id), "zclassic-main");
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    if (vcs_package_release_id(&rel, id) != VCS_PACKAGE_RELEASE_OK)
        return false;
    struct uint256 h;
    memcpy(h.data, id, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(&sk, &h, compact))
        return false;
    memcpy(rel.signature, compact + 1, VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
    uint8_t *relwire = NULL;
    size_t rellen = 0;
    if (vcs_package_release_serialize(&rel, &relwire, &rellen) !=
        VCS_PACKAGE_RELEASE_OK)
        return false;
    char id_hex[65];
    zcl_hex_encode(id, 32, id_hex);
    (void)snprintf(path, sizeof(path), "%s/releases/%s", zcode, id_hex);
    ok = rlc_write_file(path, relwire, rellen);
    free(relwire);
    return ok;
}

/* Plan + commit one published package through the REAL production lifecycle,
 * then bind the exact installed receipt: installed_inspect names the filed
 * receipt id and receipt_read re-derives the accepted program digest. This
 * is the production accepted-artifact producer the contract asserts on. */
static bool rlc_install(const char *base, const char *name,
                        const uint8_t root[32], const char *program,
                        uint8_t receipt_id_out[32],
                        char artifact_sha3_out[65])
{
    const int64_t t0 = 1700000000;
    struct package_lifecycle_plan_report plan;
    struct zcl_result r = package_lifecycle_plan(base, name, t0, &plan);
    if (!r.ok || !plan.ready) {
        printf("[plan for %s failed: rule=%s msg=%s] ", name, plan.rule,
               r.ok ? "<none>" : r.message);
        return false;
    }
    struct package_lifecycle_commit_report commit;
    struct zcl_result cr =
        package_lifecycle_commit(base, plan.plan_id, t0 + 1, &commit);
    if (!cr.ok || !commit.installed) {
        printf("[commit for %s failed: rule=%s detail=%s msg=%s] ", name,
               commit.rule, commit.detail, cr.ok ? "<none>" : cr.message);
        return false;
    }
    struct package_lifecycle_step step;
    bool installed = false;
    struct zcl_result ir =
        package_lifecycle_installed_inspect(base, root, &step, &installed);
    if (!ir.ok || !installed || !step.has_receipt)
        return false;
    memcpy(receipt_id_out, step.receipt_id, 32);
    struct vcs_package_build_receipt receipt;
    memset(&receipt, 0, sizeof(receipt));
    struct zcl_result rr =
        package_lifecycle_receipt_read(base, receipt_id_out, &receipt);
    if (!rr.ok || !vcs_package_build_installable(&receipt))
        return false;
    for (size_t i = 0; i < receipt.output_count; ++i) {
        if (strcmp(receipt.outputs[i].path, program) == 0) {
            zcl_hex_encode(receipt.outputs[i].sha3, 32, artifact_sha3_out);
            return true;
        }
    }
    return false;
}

/* The parker's resident program: answers READY under the nonce, then parks
 * forever — the unresponsive candidate the consumer's bounded result wait
 * must refuse, leaving no child behind. */
#define RLC_PARKER_MAIN \
    "#include <stdint.h>\n" \
    "#include <string.h>\n" \
    "#include <unistd.h>\n" \
    "struct parker_frame { char magic[16]; char nonce[65]; uint32_t len; };\n" \
    "int main(int argc, char **argv) {\n" \
    "  if (argc != 3 || strcmp(argv[1], \"--resident\") != 0) return 2;\n" \
    "  if (strlen(argv[2]) != 64) return 2;\n" \
    "  struct parker_frame frame;\n" \
    "  memset(&frame, 0, sizeof(frame));\n" \
    "  memcpy(frame.magic, \"z23-res-run-v1\", sizeof(\"z23-res-run-v1\"));\n" \
    "  memcpy(frame.nonce, argv[2], 64);\n" \
    "  frame.len = 5;\n" \
    "  if (write(3, &frame, sizeof(frame)) != (ssize_t)sizeof(frame)) return 3;\n" \
    "  if (write(3, \"READY\", 5) != 5) return 3;\n" \
    "  for (;;) pause();\n" \
    "}\n"

#define RLC_PARKER_H \
    "#pragma once\n" \
    "int parker_answer(void);\n"

#define RLC_PARKER_C \
    "#include \"parker.h\"\n" \
    "int parker_answer(void){ return 42; }\n"

#define RLC_PARKER_TEST \
    "#include \"parker.h\"\n" \
    "int main(void){ return parker_answer() == 42 ? 0 : 1; }\n"

#define RLC_LICENSE "Apache License 2.0\n\nLicensed under the Apache License...\n"

/* Publish + install both fixture packages into one zcode store. Returns the
 * ztasks binding the run stages invoke. */
static bool rlc_install_fixtures(const char *base, const char *zcode,
                                 uint8_t ztasks_root[32],
                                 uint8_t ztasks_receipt[32],
                                 char ztasks_sha3[65],
                                 uint8_t parker_root[32],
                                 uint8_t parker_receipt[32],
                                 char parker_sha3[65])
{
    if (!rlc_mkdir_p(zcode)) {
        printf("[cannot create the fixture zcode store] ");
        return false;
    }
    if (!rlc_executable("build/bin/zclassic23-package-verify-dev")) {
        printf("[build/bin/zclassic23-package-verify-dev missing "
               "(make dev-bin) — loud failure, never a skip] ");
        return false;
    }

    const char *const ztasks_paths[] = {
        "LICENSE", "README.md", "app/main.c", "include/ztasks/ztasks.h",
        "src/ztasks.c", "tests/test_ztasks.c",
    };
    struct rlc_file ztasks_files[6];
    for (size_t i = 0; i < 6; i++) {
        char path[512];
        (void)snprintf(path, sizeof(path), "%s/%s", RLC_ZTASKS_DIR,
                       ztasks_paths[i]);
        ztasks_files[i].path = ztasks_paths[i];
        ztasks_files[i].content = rlc_slurp(path, &ztasks_files[i].len);
        if (!ztasks_files[i].content) {
            printf("[cannot read the real ztasks package byte %s] ", path);
            for (size_t j = 0; j < i; j++)
                free((void *)ztasks_files[j].content);
            return false;
        }
    }
    bool published = rlc_publish(zcode, "ztasks/ztasks", "0.2.0", 1,
                                 ztasks_files, 6, "include/ztasks/ztasks.h",
                                 "src/ztasks.c", "tests/test_ztasks.c",
                                 "include", "app/main.c", ztasks_root);
    for (size_t i = 0; i < 6; i++)
        free((void *)ztasks_files[i].content);
    if (!published) {
        printf("[ztasks publish failed] ");
        return false;
    }
    if (!rlc_install(base, "ztasks/ztasks", ztasks_root, RLC_ZTASKS_PROGRAM,
                     ztasks_receipt, ztasks_sha3)) {
        printf("[ztasks install/bind failed] ");
        return false;
    }

    const struct rlc_file parker_files[] = {
        { "LICENSE", RLC_LICENSE, sizeof(RLC_LICENSE) - 1u },
        { "src/parker.h", RLC_PARKER_H, sizeof(RLC_PARKER_H) - 1u },
        { "src/parker.c", RLC_PARKER_C, sizeof(RLC_PARKER_C) - 1u },
        { "test/test_parker.c", RLC_PARKER_TEST, sizeof(RLC_PARKER_TEST) - 1u },
        { "app/main.c", RLC_PARKER_MAIN, sizeof(RLC_PARKER_MAIN) - 1u },
    };
    if (!rlc_publish(zcode, "rlc/parker", "0.1.0", 2, parker_files, 5,
                     "src/parker.h", "src/parker.c", "test/test_parker.c",
                     "src", "app/main.c", parker_root)) {
        printf("[parker publish failed] ");
        return false;
    }
    if (!rlc_install(base, "rlc/parker", parker_root, RLC_PARKER_PROGRAM,
                     parker_receipt, parker_sha3)) {
        printf("[parker install/bind failed] ");
        return false;
    }
    return true;
}

/* One explicit consumer invocation under C's concrete schema (see the
 * ADAPTER SEAM): every key named, accept_execution a JSON boolean. */
static void rlc_call_package(struct rlc_call *c,
                             const struct zcl_command_spec *spec,
                             const char *datadir, const char *root_hex,
                             const char *receipt_hex, const char *sha3_hex,
                             const char *program, const char *input_text)
{
    rlc_begin(c, spec);
    (void)json_push_kv_str(&c->input, "datadir", datadir);
    (void)json_push_kv_str(&c->input, "package_root", root_hex);
    (void)json_push_kv_str(&c->input, "receipt_id", receipt_hex);
    (void)json_push_kv_str(&c->input, "artifact_sha3", sha3_hex);
    (void)json_push_kv_str(&c->input, "program", program);
    (void)json_push_kv_str(&c->input, "input_text", input_text);
    (void)json_push_kv_bool(&c->input, "accept_execution", true);
}

/* ── stage-f trap fixtures ──────────────────────────────────────────────── */

/* One installed generation binding, hex-encoded for the serving-mode
 * calls: the identity the stage-f trap threads through accept/activate/
 * rollback. */
struct rlc_binding {
    uint8_t root[32];
    uint8_t receipt[32];
    char root_hex[65];
    char receipt_hex[65];
    char sha3[65];
};

static void rlc_binding_fill(struct rlc_binding *out, const uint8_t root[32],
                             const uint8_t receipt[32], const char sha3[65])
{
    memcpy(out->root, root, 32);
    memcpy(out->receipt, receipt, 32);
    zcl_hex_encode(root, 32, out->root_hex);
    zcl_hex_encode(receipt, 32, out->receipt_hex);
    (void)snprintf(out->sha3, sizeof(out->sha3), "%s", sha3);
}

/* Splice `replacement` over the first occurrence of `needle` in the
 * slurped `text` (NUL-terminated, `len` content bytes). Returns a new
 * malloc'd string, NULL when the needle is absent or allocation fails. */
static char *rlc_splice_text(const char *text, size_t len,
                             const char *needle, const char *replacement)
{
    const char *hit = strstr(text, needle);
    if (!hit)
        return NULL;
    size_t head = (size_t)(hit - text);
    size_t nlen = strlen(needle);
    size_t rlen = strlen(replacement);
    size_t out_len = len - nlen + rlen;
    char *out = malloc(out_len + 1u);
    if (!out)
        return NULL;
    memcpy(out, text, head);
    memcpy(out + head, replacement, rlen);
    memcpy(out + head + rlen, hit + nlen, len - head - nlen);
    out[out_len] = '\0';
    return out;
}

/* One edited ztasks generation (different program bytes → a different
 * artifact digest) to play N+1 / N+2 / B against N in the stage-f trap:
 * the REAL package files with the empty-list render line patched,
 * published as a higher semver and installed by its exact root. */
enum rlc_preview_fault { RLC_PREVIEW_OK, RLC_PREVIEW_WRONG_ID,
                         RLC_PREVIEW_CRASH, RLC_PREVIEW_BAD_ABI };

static bool rlc_install_ztasks_variant(const char *base, const char *zcode,
                                       const char *semver, uint64_t sequence,
                                       const char *list_line, enum rlc_preview_fault fault,
                                       struct rlc_binding *out)
{
    const char *const paths[] = {
        "LICENSE", "README.md", "app/main.c", "include/ztasks/ztasks.h",
        "src/ztasks.c", "tests/test_ztasks.c",
    };
    struct rlc_file files[6];
    for (size_t i = 0; i < 6; i++) {
        char path[512];
        (void)snprintf(path, sizeof(path), "%s/%s", RLC_ZTASKS_DIR,
                       paths[i]);
        files[i].path = paths[i];
        files[i].content = rlc_slurp(path, &files[i].len);
        if (!files[i].content) {
            for (size_t j = 0; j < i; j++)
                free((void *)files[j].content);
            return false;
        }
        if (strcmp(paths[i], "app/main.c") == 0) {
            char *empty = rlc_splice_text(files[i].content, files[i].len,
                                          "No tasks yet.", list_line);
            char *visible = empty ? rlc_splice_text(empty, strlen(empty),
                "state->tasks[i].done ? \"DONE\" : \"OPEN\"",
                "state->tasks[i].done ? \"DONE\" : \"TODO\"") : NULL;
            char *isolated = visible ? rlc_splice_text(visible, strlen(visible),
                "static int task_preview(char **argv)\n{",
                "static int task_preview(char **argv)\n{\n"
                "    char inherited;\n"
                "    if (getenv(\"Z23_PREVIEW_SECRET\") ||\n"
                "        read(200, &inherited, 1) >= 0 || errno != EBADF) return 9;") : NULL;
            free(empty);
            free(visible);
            if (isolated && fault != RLC_PREVIEW_OK) {
                const char *needle = fault == RLC_PREVIEW_WRONG_ID
                    ? "(unsigned long long)state->tasks[i].id,"
                    : fault == RLC_PREVIEW_CRASH
                    ? "static int task_preview(char **argv)\n{"
                    : "printf(\"READY %s\\n\", argv[2]);";
                const char *replacement = fault == RLC_PREVIEW_WRONG_ID
                    ? "(unsigned long long)(state->tasks[i].id + 1u),"
                    : fault == RLC_PREVIEW_CRASH
                    ? "static int task_preview(char **argv)\n{\n    raise(SIGSEGV);"
                    : "printf(\"WRONG %s\\n\", argv[2]);";
                char *faulted = rlc_splice_text(isolated, strlen(isolated),
                                                needle, replacement);
                free(isolated);
                isolated = faulted;
            }
            if (!isolated) {
                for (size_t j = 0; j <= i; j++)
                    free((void *)files[j].content);
                return false;
            }
            free((void *)files[i].content);
            files[i].content = isolated;
            files[i].len = strlen(isolated);
        }
    }
    uint8_t root[32], receipt[32];
    char sha3[65];
    bool ok = rlc_publish(zcode, "ztasks/ztasks", semver, sequence, files, 6,
                          "include/ztasks/ztasks.h", "src/ztasks.c",
                          "tests/test_ztasks.c", "include", "app/main.c",
                          root);
    for (size_t i = 0; i < 6; i++)
        free((void *)files[i].content);
    if (!ok)
        return false;
    char root_hex[65];
    zcl_hex_encode(root, 32, root_hex);
    /* Plan by the exact 64-hex root (identity), never by name: the name
     * selects the highest semver, which is not the generation under test. */
    if (!rlc_install(base, root_hex, root, RLC_ZTASKS_PROGRAM, receipt,
                     sha3))
        return false;
    rlc_binding_fill(out, root, receipt, sha3);
    return true;
}

/* Force a serving generation's failure the hostile way: same-length
 * corruption of the installed program bytes, so the receipt-bound
 * re-hash (never a pathname, never equivalent bytes) is what refuses.
 * The fixture datadir is test-owned. */
/* Real installed programs, real confined preview, and the same native actions
 * as the window. No desktop or synthetic compatibility callback required. */
static bool rlc_task_wait(struct task_update *update)
{
    int64_t deadline = platform_time_monotonic_us() + INT64_C(15000000);
    while (update->pending && platform_time_monotonic_us() < deadline) {
        bool changed = false;
        if (!task_update_poll(update, &changed).ok) return false;
        if (update->pending && (update->phase == TASK_UPDATE_KEPT ||
            update->phase == TASK_UPDATE_READY || strstr(update->message, "restored"))) return false;
        (void)sched_yield();
    }
    return !update->pending;
}

static struct package_resident_identity rlc_task_identity(const struct rlc_binding *binding)
{
    struct package_resident_identity identity = { .configuration_generation = 1 };
    (void)snprintf(identity.package_root, sizeof(identity.package_root), "%s", binding->root_hex);
    (void)snprintf(identity.receipt_id, sizeof(identity.receipt_id), "%s", binding->receipt_hex);
    (void)snprintf(identity.artifact_sha3, sizeof(identity.artifact_sha3), "%s", binding->sha3);
    (void)snprintf(identity.program, sizeof(identity.program), "%s", RLC_ZTASKS_PROGRAM);
    return identity;
}

static bool rlc_task_equal(const struct task_document *a, const struct task_document *b)
{
    unsigned char x[TA_PAYLOAD], y[TA_PAYLOAD];
    uint32_t nx, ny;
    if (a->can_undo != b->can_undo || !ta_state_encode(&a->state, x, &nx) ||
        !ta_state_encode(&b->state, y, &ny) || nx != ny || memcmp(x, y, nx)) return false;
    return ta_state_encode(&a->undo, x, &nx) && ta_state_encode(&b->undo, y, &ny) &&
        nx == ny && memcmp(x, y, nx) == 0;
}

static bool rlc_task_try_keep(struct task_update *update)
{
    return task_update_try(update, true, false).ok && rlc_task_wait(update) &&
        task_update_keep(update).ok && rlc_task_wait(update);
}

static int rlc_task_typing(struct task_editor *editor)
{
    int failures = 0;
    int64_t before = platform_time_monotonic_us();
    struct zcl_result typed = ZCL_OK;
    const char *text = "Typing while preview runs";
    for (size_t i = 0; text[i] && typed.ok; ++i)
        typed = task_editor_type(editor, (uint8_t)text[i], false);
    struct zcl_present_model_v1 model;
    struct zcl_result rendered = task_editor_model(editor, &model);
    struct zcl_present_model_bitmap_v1 frame = {0};
    char error[256];
    bool pixels = rendered.ok && zcl_present_model_render_editor_v1(&model, &frame, error, sizeof(error));
    int64_t elapsed = platform_time_monotonic_us() - before;
    RLC_CHECK("task updates: typing reaches real frame while preview runs", typed.ok && pixels && elapsed < 50000);
    printf("task updates: input_to_frame_us=%lld\n", (long long)elapsed);
    zcl_present_model_bitmap_free_v1(&frame);
    return failures;
}

static int rlc_task_focus(struct task_list *list)
{
    int failures = 0;
    struct zcl_present_model_v1 model;
    struct zcl_present_model_bitmap_v1 first = {0}, next = {0};
    char error[256];
    bool rendered = task_list_model(list, &model).ok &&
        zcl_present_model_render_list_v1(&model, &first, error, sizeof(error)) &&
        zcl_present_model_render_list_v1(&model, &next, error, sizeof(error));
    RLC_CHECK("task updates: render actual permission page", rendered);
    if (rendered) {
        struct zcl_present_window_v1 page = { .pixels = first.pixels, .width = first.width, .height = first.height, .pixel_format = ZCL_PRESENT_RGB8 };
        zcl_present_draw_action_focus_internal(&page, first.pixels, first.width, first.height, 4, list->focus);
        struct zcl_present_input_v1 tab = { .key = ZCL_PRESENT_INPUT_TAB };
        uint32_t action = UINT32_MAX;
        bool moved = task_list_input(list, &tab, &list->focus, &action);
        zcl_present_draw_action_focus_internal(&page, next.pixels, next.width, next.height, 4, list->focus);
        RLC_CHECK("task updates: Tab changes visible native focus", moved && list->focus == 1 &&
            memcmp(first.pixels, next.pixels, ZCL_PRESENT_MODEL_BITMAP_BYTES) != 0);
    }
    zcl_present_model_bitmap_free_v1(&first);
    zcl_present_model_bitmap_free_v1(&next);
    return failures;
}

static int rlc_task_panel(struct task_update *update, struct task_editor *editor)
{
    int failures = 0;
    struct task_list list;
    task_list_init(&list, editor);
    list.update = update;
    list.menu = true;
    RLC_CHECK("task updates: native menu opens Updates", task_list_action(&list, 3).ok && list.updates);
    RLC_CHECK("task updates: Try asks permission without execution", task_list_action(&list, 0).ok && list.permission == 1 && !update->pending);
    struct zcl_present_model_v1 model;
    RLC_CHECK("task updates: permission is visible", task_list_model(&list, &model).ok &&
        strstr(model.title, "Allow") && strcmp(model.actions[0].label, "Allow preview") == 0);
    failures += rlc_task_focus(&list);
    RLC_CHECK("task updates: cancel permission keeps code inert", task_list_action(&list, 1).ok && !list.permission && !update->pending);
    RLC_CHECK("task updates: explicit Allow starts isolated execution", task_list_action(&list, 0).ok &&
        task_list_action(&list, 0).ok && update->pending);
    failures += rlc_task_typing(editor);
    RLC_CHECK("task updates: preview completes separately", rlc_task_wait(update));
    RLC_CHECK("task updates: discard never changes live contents", task_list_action(&list, 1).ok && !update->ready);
    return failures;
}

struct rlc_task_session {
    const char *base, *verifier;
    struct package_resident_store *store;
    struct task_document *document, *expected;
    struct task_update *update;
    const struct rlc_binding *n, *n1, *n2, *broken;
};

static int rlc_task_edits(const struct rlc_task_session *session)
{
    int failures = 0;
    session->update->candidate = rlc_task_identity(session->n1);
    RLC_CHECK("task journey: edit before preview", task_document_apply(session->store, session->document->state.revision,
        TASK_DOCUMENT_EDIT, session->document->state.tasks[0].id, "Edited before preview", session->document).ok);
    /* The verifier inherits these from its caller. Candidate code probes
     * both before it renders: the preview child must see neither. */
    int secret = open("/dev/null", O_RDONLY);
    bool fd_armed = secret >= 0 && fcntl(200, F_GETFD) < 0 &&
        errno == EBADF && dup2(secret, 200) == 200;
    bool private_inputs = fd_armed &&
        setenv("Z23_PREVIEW_SECRET", "fixture-secret", 1) == 0;
    if (secret >= 0) (void)close(secret);
    RLC_CHECK("task journey: inheritable descriptor and environment probe armed", private_inputs);
    bool previewed = private_inputs && task_update_try(session->update, true, false).ok &&
        rlc_task_wait(session->update);
    if (private_inputs) (void)unsetenv("Z23_PREVIEW_SECRET");
    if (fd_armed) (void)close(200);
    RLC_CHECK("task journey: NEW compiled preview behavior is visible with no inherited secret",
        previewed && strstr(session->update->preview, "[TODO] Edited before preview") &&
        strstr(session->update->active, "[OPEN] Keep this exact task"));
    RLC_CHECK("task journey: edit while preview exists", task_document_apply(session->store, session->document->state.revision,
        TASK_DOCUMENT_EDIT, session->document->state.tasks[0].id, "Newer edit must survive", session->document).ok);
    *session->expected = *session->document;
    RLC_CHECK("task journey: stale Keep refuses clearly", task_update_keep(session->update).ok &&
        !rlc_task_wait(session->update) && session->update->phase == TASK_UPDATE_FAILED);
    RLC_CHECK("task journey: stale preview never imports old data", task_document_read(session->store, session->document).ok && rlc_task_equal(session->document, session->expected));
    RLC_CHECK("task journey: fresh preview then Keep", rlc_task_try_keep(session->update));
    return failures;
}

static int rlc_task_return(const struct rlc_task_session *session)
{
    int failures = 0;
    RLC_CHECK("task journey: close", task_update_finish(session->update).ok && package_resident_store_close(session->store).ok);
    RLC_CHECK("task journey: reopen exact data plus undo", package_resident_store_open_app(session->store, session->base, "contract/task-journey").ok &&
        task_document_read(session->store, session->document).ok && rlc_task_equal(session->document, session->expected) &&
        task_update_open(session->update, session->base, session->store->app, session->verifier, NULL).ok && task_update_refresh(session->update).ok && rlc_task_wait(session->update));
    RLC_CHECK("task journey: prior program understands CURRENT data before Go back", task_update_try(session->update, true, true).ok && rlc_task_wait(session->update));
    struct package_resident_record record;
    RLC_CHECK("task journey: exact prior artifact restored without restoring old data", package_resident_record_read(session->store, &record).ok &&
        strcmp(record.current.artifact_sha3, session->n->sha3) == 0 && task_document_read(session->store, session->document).ok && rlc_task_equal(session->document, session->expected));
    return failures;
}

static int rlc_task_failed_program(const struct rlc_task_session *session)
{
    int failures = 0;
    struct package_resident_record before, after;
    session->update->candidate = rlc_task_identity(session->broken);
    (void)snprintf(session->update->candidate.program,
        sizeof(session->update->candidate.program), "%s", RLC_PARKER_PROGRAM);
    bool read = package_resident_record_read(session->store, &before).ok;
    RLC_CHECK("task journey: incompatible preview fails after confined execution",
        task_update_try(session->update, true, false).ok &&
        !rlc_task_wait(session->update) && session->update->phase == TASK_UPDATE_FAILED &&
        strstr(session->update->message, "compatibility"));
    RLC_CHECK("task journey: failed program leaves current program, tasks and undo intact",
        read && package_resident_record_read(session->store, &after).ok &&
        package_resident_identity_equal(&before.current, &after.current) &&
        task_document_read(session->store, session->document).ok &&
        rlc_task_equal(session->document, session->expected));
    return failures;
}

static int rlc_task_failures(const struct rlc_task_session *session)
{
    int failures = 0;
    struct package_resident_record record;
    session->update->candidate = rlc_task_identity(session->n1);
    RLC_CHECK("task journey: cancellation preserves data", task_update_try(session->update, true, false).ok);
    task_update_cancel(session->update);
    (void)rlc_task_wait(session->update);
    RLC_CHECK("task journey: cancelled preview cannot Keep", !session->update->pending && !session->update->ready &&
        !task_update_keep(session->update).ok && task_document_read(session->store, session->document).ok && rlc_task_equal(session->document, session->expected));
    session->update->candidate.artifact_sha3[0] = session->update->candidate.artifact_sha3[0] == '0' ? '1' : '0';
    RLC_CHECK("task journey: changed artifact fails without changing program", task_update_try(session->update, true, false).ok &&
        !rlc_task_wait(session->update) && package_resident_record_read(session->store, &record).ok && strcmp(record.current.artifact_sha3, session->n->sha3) == 0);
    session->update->candidate = rlc_task_identity(session->n1);
    RLC_CHECK("task journey: N to N+1", rlc_task_try_keep(session->update));
    session->update->candidate = rlc_task_identity(session->n2);
    RLC_CHECK("task journey: N+1 to N+2", rlc_task_try_keep(session->update));
    RLC_CHECK("task journey: newer version retains exact data and undo", task_document_read(session->store, session->document).ok && rlc_task_equal(session->document, session->expected));
    return failures;
}

static int rlc_task_cycles(const struct rlc_task_session *session)
{
    int failures = 0;
    int64_t maximum_us = 0;
    bool cycles_passed = true;
    for (unsigned cycle = 0; cycle < 20 && cycles_passed; ++cycle) {
        cycles_passed = task_update_try(session->update, true, true).ok && rlc_task_wait(session->update) &&
            task_document_read(session->store, session->document).ok && rlc_task_equal(session->document, session->expected);
        if (session->update->elapsed_us > maximum_us) maximum_us = session->update->elapsed_us;
        printf("task return cycle=%u total_us=%lld helper_startup_us=%lld confined_us=%lld", cycle,
            (long long)session->update->elapsed_us, (long long)session->update->helper_startup_us,
            (long long)session->update->confined_us);
        for (unsigned step = 0; step < TASK_UPDATE_STEP_COUNT; ++step)
            printf(" step%u_us=%lld", step, (long long)session->update->step_us[step]);
        putchar('\n');

    }
    RLC_CHECK("task journey: 20 confined compatibility checks and exact returns", cycles_passed);
    printf("task journey: return maximum_us=%lld real_gui=OPEN\n", (long long)maximum_us);
    RLC_CHECK("task journey: undo survives all program changes", task_document_apply(session->store, session->document->state.revision,
        TASK_DOCUMENT_UNDO, 0, NULL, session->document).ok && strcmp(session->document->state.tasks[0].title, "Edited before preview") == 0);
    return failures;
}

static int rlc_task_snapshot_reuse(const char *base, const struct rlc_binding *binding)
{
    int failures = 0;
    uint8_t root[32], receipt[32];
    struct package_resident_artifact artifact;
    struct package_resident image;
    package_resident_init(&image);
    bool prepared = zcl_hex_decode_lower(binding->root_hex, root, 32) &&
        zcl_hex_decode_lower(binding->receipt_hex, receipt, 32) &&
        package_resident_artifact_read(base, root, receipt, RLC_ZTASKS_PROGRAM, &artifact).ok &&
        package_resident_prepare(&image, &artifact).ok;
    RLC_CHECK("task return: independent snapshot prepared", prepared);
    if (prepared) {
        uint64_t inode = image.launch.accepted.image_low;
        char nonce[65];
        (void)snprintf(nonce, sizeof(nonce), "%s", image.launch.nonce);
        RLC_CHECK("task return: retained bytes reverified with fresh nonce", package_resident_prepare_reuse(&image, &artifact).ok &&
            image.launch.accepted.image_low == inode && strcmp(nonce, image.launch.nonce) != 0);
        FILE *file = chmod(image.snapshot_image, 0700) == 0 ? fopen(image.snapshot_image, "r+b") : NULL;
        bool corrupted = file && fputc('X', file) != EOF;
        if (file && fclose(file) != 0) corrupted = false;
        RLC_CHECK("task return: changed retained snapshot refuses", corrupted &&
            !package_resident_prepare_reuse(&image, &artifact).ok);
        RLC_CHECK("task return: snapshot failure leaves installed artifact intact",
            package_resident_artifact_read(base, root, receipt, RLC_ZTASKS_PROGRAM, &artifact).ok);
    }
    RLC_CHECK("task return: retained snapshot released", package_resident_close(&image).ok);
    return failures;
}

static int rlc_task_journey(const char *base, const struct rlc_binding *n,
                            const struct rlc_binding *n1, const struct rlc_binding *n2,
                            const struct rlc_binding *broken)
{
    int failures = 0;
    size_t fd_before = 0, fd_after = 0;
    bool counted = os_proc_open_fd_count(&fd_before);
    char verifier[4096];
    if (!realpath("build/bin/zclassic23-package-verify-dev", verifier)) return 1;
    struct package_resident_store store = {0};
    struct task_document document = {0}, expected = {0};
    struct package_resident_identity first = rlc_task_identity(n);
    struct task_update update = {0};
    bool opened = package_resident_store_open_app(&store, base, "contract/task-journey").ok &&
        task_document_apply(&store, 0, TASK_DOCUMENT_ADD, 0, "Keep this exact task", &document).ok &&
        task_update_open(&update, base, store.app, verifier, &first).ok;
    RLC_CHECK("task journey: durable task and update owner open", opened);
    if (!opened) { (void)package_resident_store_close(&store); return failures; }
    RLC_CHECK("task journey: no execution without permission", !task_update_try(&update, false, false).ok && !update.pending);
    RLC_CHECK("task journey: first program preview and Keep", rlc_task_try_keep(&update));
    struct task_editor editor;
    if (task_editor_open(&editor, base, store.app).ok) {
        failures += rlc_task_panel(&update, &editor);
        RLC_CHECK("task updates: close saves typed draft durably", task_editor_finish(&editor).ok &&
            task_document_read(&store, &document).ok);
    } else ++failures;
    const struct rlc_task_session session = { base, verifier, &store, &document, &expected, &update, n, n1, n2, broken };
    failures += rlc_task_edits(&session);
    failures += rlc_task_return(&session);
    failures += rlc_task_failed_program(&session);
    failures += rlc_task_failures(&session);
    failures += rlc_task_cycles(&session);
    failures += rlc_task_snapshot_reuse(base, n);
    (void)task_update_finish(&update);
    (void)package_resident_store_close(&store);
    RLC_CHECK("task journey: descriptor count unchanged", counted && os_proc_open_fd_count(&fd_after) && fd_before == fd_after);
    return failures;
}

static int rlc_preview_time_order(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

/* Each sample edits package C, builds a distinct artifact, then observes its
 * new output through the confined Try path while N remains accepted. */
static int rlc_task_preview_latency(const char *base, const char *zcode,
                                    const struct rlc_binding *n)
{
    int failures = 0;
    char verifier[4096];
    if (!realpath("build/bin/zclassic23-package-verify-dev", verifier)) return 1;
    struct package_resident_store store = {0};
    struct task_update update = {0};
    struct package_resident_identity accepted = rlc_task_identity(n);
    bool opened = package_resident_store_open_app(&store, base,
        "contract/task-preview-latency").ok &&
        task_update_open(&update, base, store.app, verifier, &accepted).ok &&
        rlc_task_try_keep(&update);
    RLC_CHECK("preview latency: accepted N serves before edits", opened &&
        strcmp(update.active, "No tasks yet.\n") == 0);
    if (!opened) goto done;
    enum os_sandbox_package_confinement confinement = os_sandbox_package_confinement();
    RLC_CHECK("preview latency: qualified host confinement is available",
              confinement != OS_SANDBOX_PACKAGE_CONFINEMENT_NONE);
    int64_t times[20], build_times[20], preview_times[20];
    unsigned measured = 0;
    for (unsigned i = 0; i < 20; ++i) {
        char version[24], line[64], expected[80];
        (void)snprintf(version, sizeof(version), "0.%u.0", i + 6u);
        (void)snprintf(line, sizeof(line), "Preview %02u", i);
        (void)snprintf(expected, sizeof(expected), "%s\n", line);
        int64_t started = platform_time_monotonic_us();
        struct rlc_binding candidate;
        bool installed = rlc_install_ztasks_variant(base, zcode, version,
            i + 6u, line, RLC_PREVIEW_OK, &candidate);
        int64_t built = platform_time_monotonic_us();
        if (installed) update.candidate = rlc_task_identity(&candidate);
        bool executed = installed && task_update_try(&update, true, false).ok &&
            rlc_task_wait(&update);
        struct package_resident_record record;
        bool preserved = executed && package_resident_record_read(&store, &record).ok &&
            package_resident_identity_equal(&record.current, &accepted) &&
            strcmp(update.active, "No tasks yet.\n") == 0 &&
            strcmp(update.preview, expected) == 0;
        RLC_CHECK("preview latency: distinct compiled bytes execute while N stays selected",
                  preserved);
        if (!preserved) {
            printf("preview fallback cycle=%u reason=%s\n", i, update.message);
            break;
        }
        int64_t elapsed = platform_time_monotonic_us() - started;
        times[measured] = elapsed;
        build_times[measured] = built - started;
        preview_times[measured] = elapsed - build_times[measured];
        ++measured;
        printf("preview sample=%u root=%s receipt=%s artifact_sha3=%s "
               "edit_to_behavior_us=%lld build_us=%lld execute_us=%lld "
               "fallback=none\n", i, candidate.root_hex, candidate.receipt_hex,
               candidate.sha3, (long long)elapsed,
               (long long)(built - started),
               (long long)(elapsed - (built - started)));
        task_update_cancel(&update);
        bool returned = task_update_refresh(&update).ok &&
            rlc_task_wait(&update) && strcmp(update.active, "No tasks yet.\n") == 0;
        RLC_CHECK("preview latency: accepted N still executes after Try", returned);
        if (!returned) break;
    }
    if (measured == 20) {
        qsort(times, measured, sizeof(times[0]), rlc_preview_time_order);
        qsort(build_times, measured, sizeof(build_times[0]), rlc_preview_time_order);
        qsort(preview_times, measured, sizeof(preview_times[0]), rlc_preview_time_order);
        printf("preview edit_to_behavior samples=20 p50_us=%lld p95_us=%lld "
               "build_p50_us=%lld build_p95_us=%lld "
               "execute_p50_us=%lld execute_p95_us=%lld "
               "fallbacks=0 accepted_sha3=%s confinement=%d\n",
               (long long)times[9], (long long)times[18],
               (long long)build_times[9], (long long)build_times[18],
               (long long)preview_times[9], (long long)preview_times[18],
               n->sha3, (int)confinement);
    }
    RLC_CHECK("preview latency: all distinct edit-to-behavior samples completed",
              measured == 20);

    struct task_document document = {0}, expected_data = {0};
    bool task_added = task_document_apply(&store, 0, TASK_DOCUMENT_ADD, 0,
        "Preserve this task", &document).ok;
    expected_data = document;
    RLC_CHECK("preview faults: accepted task data prepared", task_added);
    if (task_added) {
        const enum rlc_preview_fault faults[] = {
            RLC_PREVIEW_WRONG_ID, RLC_PREVIEW_CRASH, RLC_PREVIEW_BAD_ABI };
        const char *const labels[] = { "behavior", "crash", "interface" };
        for (unsigned i = 0; i < 3; ++i) {
            char version[24], line[64];
            (void)snprintf(version, sizeof(version), "0.%u.0", i + 26u);
            (void)snprintf(line, sizeof(line), "Fault %u", i);
            struct rlc_binding candidate;
            bool installed = rlc_install_ztasks_variant(base, zcode, version,
                i + 26u, line, faults[i], &candidate);
            if (installed) update.candidate = rlc_task_identity(&candidate);
            bool refused = installed && task_update_try(&update, true, false).ok &&
                !rlc_task_wait(&update) && update.phase == TASK_UPDATE_FAILED;
            struct package_resident_record record;
            bool fallback = refused && package_resident_record_read(&store, &record).ok &&
                package_resident_identity_equal(&record.current, &accepted) &&
                task_document_read(&store, &document).ok &&
                rlc_task_equal(&document, &expected_data);
            RLC_CHECK("preview faults: bad behavior, crash or interface retains N and data",
                      fallback);
            printf("preview fallback kind=%s reason=%s\n", labels[i], update.message);
        }
    }
done:
    (void)task_update_finish(&update);
    (void)package_resident_store_close(&store);
    return failures;
}

static bool rlc_corrupt_installed(const char *base, const char *root_hex,
                                  const char *program)
{
    char path[4500];
    (void)snprintf(path, sizeof(path), "%s/zcode/installed/%s/%s", base,
                   root_hex, program);
    FILE *f = fopen(path, "r+b");
    if (!f)
        return false;
    unsigned char garbage[64];
    memset(garbage, 0xA5, sizeof(garbage));
    bool ok = fwrite(garbage, 1, sizeof(garbage), f) == sizeof(garbage);
    if (fclose(f) != 0)
        ok = false;
    return ok;
}

/* Keep a valid accepted candidate's exact bytes intact while making only
 * its isolated install locator unavailable to activation's fresh proof. */
static bool rlc_candidate_locator(const char *base, const char *root_hex,
                                   bool restore)
{
    char path[4500], held[4516];
    int n = snprintf(path, sizeof(path), "%s/zcode/installed/%s/%s", base,
                     root_hex, RLC_ZTASKS_PROGRAM);
    if (n < 0 || (size_t)n >= sizeof(path)) return false;
    n = snprintf(held, sizeof(held), "%s.f7-held", path);
    if (n < 0 || (size_t)n >= sizeof(held)) return false;
    const char *source = restore ? held : path;
    const char *destination = restore ? path : held;
    struct stat st;
    if (lstat(destination, &st) == 0 || errno != ENOENT) return false;
    if (lstat(source, &st) != 0 || !S_ISREG(st.st_mode)) return false;
    return rename(source, destination) == 0;
}

#define RLC_APP "ztasks/ztasks"

/* One serving-mode invocation of the stage-f contract (see the ADAPTER
 * SEAM stage-f block): app + action select the serving-record operation;
 * the receipt triple + program are present only where the action binds
 * exact bytes (accept, or a stale named invoke). */
static void rlc_call_serving(struct rlc_call *c,
                             const struct zcl_command_spec *spec,
                             const char *datadir, const char *app,
                             const char *action, const char *root_hex,
                             const char *receipt_hex, const char *sha3_hex,
                             const char *program, const char *input_text)
{
    rlc_begin(c, spec);
    (void)json_push_kv_str(&c->input, "datadir", datadir);
    (void)json_push_kv_str(&c->input, "app", app);
    (void)json_push_kv_str(&c->input, "action", action);
    if (root_hex)
        (void)json_push_kv_str(&c->input, "package_root", root_hex);
    if (receipt_hex)
        (void)json_push_kv_str(&c->input, "receipt_id", receipt_hex);
    if (sha3_hex)
        (void)json_push_kv_str(&c->input, "artifact_sha3", sha3_hex);
    if (program)
        (void)json_push_kv_str(&c->input, "program", program);
    (void)json_push_kv_str(&c->input, "input_text", input_text);
    (void)json_push_kv_bool(&c->input, "accept_execution", true);
}


/* ── stage 0: reference-child fixture self-check (platform seam only) ─────
 * Green today: proves the fixture above speaks the exact wire bytes of the
 * landed consumer (READY gate, one nonce-bound run frame round-trip,
 * cancel/reap) through the real resident_launch seam. NOT part of the
 * product contract. */
static int rlc_fixture_selfcheck(const char *child,
                                 const struct resident_launch_accepted *acc)
{
    int failures = 0;
    char error[RESIDENT_LAUNCH_ERROR_MAX];
    struct resident_launch launch;
    resident_launch_init(&launch);
    error[0] = '\0';
    RLC_CHECK("stage 0 (fixture): prepare the reference child",
              resident_launch_prepare(&launch, child, acc, error,
                                      sizeof(error)));
    char *const argv[] = {(char *)child, (char *)"--resident",
                          launch.nonce, NULL};
    char *const envp[] = {NULL};
    struct resident_receipt receipt;
    memset(&receipt, 0, sizeof(receipt));
    error[0] = '\0';
    bool spawned = resident_launch_spawn(&launch, argv, envp, &receipt, error,
                                         sizeof(error));
    if (!spawned)
        printf("[spawn error: %s (errno=%d)] ", error[0] ? error : "<none>",
               errno);
    RLC_CHECK("stage 0 (fixture): spawn maps the exact accepted image",
              spawned);
    struct resident_result_header header;
    unsigned char payload[128];
    error[0] = '\0';
    RLC_CHECK("stage 0 (fixture): READY frame accepted under the nonce",
              resident_result_read(&launch, &header, payload, sizeof(payload),
                                   5000, error, sizeof(error)) &&
              header.payload_len == 5 &&
              memcmp(payload, "READY", 5) == 0);
    error[0] = '\0';
    RLC_CHECK("stage 0 (fixture): one run frame round-trips the exact "
              "payload",
              rlc_send_frame(&launch, "fixture-roundtrip") &&
              resident_result_read(&launch, &header, payload, sizeof(payload),
                                   5000, error, sizeof(error)) &&
              header.payload_len == strlen("fixture-roundtrip") &&
              memcmp(payload, "fixture-roundtrip",
                     strlen("fixture-roundtrip")) == 0);
    error[0] = '\0';
    RLC_CHECK("stage 0 (fixture): cancel reaps the reference child",
              resident_launch_cancel(&launch, 300, error, sizeof(error)) &&
              rlc_wait_reaped(receipt.pid));
    resident_launch_close(&launch);

    /* The parking variant: READY, then unresponsive — cancel must still
     * reap it inside the budget. */
    resident_launch_init(&launch);
    error[0] = '\0';
    bool parked = resident_launch_prepare(&launch, child, acc, error,
                                          sizeof(error));
    char *const park_argv[] = {(char *)child, (char *)"--resident",
                               launch.nonce, (char *)"park", NULL};
    error[0] = '\0';
    parked = parked &&
        resident_launch_spawn(&launch, park_argv, envp, &receipt, error,
                              sizeof(error)) &&
        resident_result_read(&launch, &header, payload, sizeof(payload),
                             5000, error, sizeof(error)) &&
        header.payload_len == 5 && memcmp(payload, "READY", 5) == 0;
    RLC_CHECK("stage 0 (fixture): the parking child passes the READY gate",
              parked);
    error[0] = '\0';
    RLC_CHECK("stage 0 (fixture): cancel reaps an unresponsive resident",
              resident_launch_cancel(&launch, 300, error, sizeof(error)) &&
              rlc_wait_reaped(receipt.pid));
    resident_launch_close(&launch);

    /* The broken candidate: exits without framing, so the READY gate must
     * refuse it — the wire-level refusal the consumer's READY read applies
     * to any installed program that does not speak the protocol. */
    struct resident_launch_accepted broken_acc;
    bool have_broken = rlc_accept_of(RLC_FIXTURE_BROKEN, &broken_acc);
    resident_launch_init(&launch);
    error[0] = '\0';
    bool broken_refused = have_broken &&
        resident_launch_prepare(&launch, RLC_FIXTURE_BROKEN, &broken_acc,
                                error, sizeof(error));
    char *const broken_argv[] = {(char *)RLC_FIXTURE_BROKEN,
                                 (char *)"--resident", launch.nonce, NULL};
    error[0] = '\0';
    broken_refused = broken_refused &&
        resident_launch_spawn(&launch, broken_argv, envp, &receipt, error,
                              sizeof(error));
    error[0] = '\0';
    broken_refused = broken_refused &&
        !resident_result_read(&launch, &header, payload, sizeof(payload),
                              5000, error, sizeof(error));
    RLC_CHECK("stage 0 (fixture): the READY gate refuses a child that "
              "never frames",
              broken_refused);
    error[0] = '\0';
    RLC_CHECK("stage 0 (fixture): cancel reaps the refused child",
              resident_launch_cancel(&launch, 300, error, sizeof(error)) &&
              rlc_wait_reaped(receipt.pid));
    resident_launch_close(&launch);
    return failures;
}

/* ── stages b/c/d: verified launch, fd-3 frame, observable result ──────── */

static int rlc_stage_run(const struct zcl_command_spec *spec,
                         const char *datadir, const char *root_hex,
                         const char *receipt_hex, const char *sha3_hex)
{
    int failures = 0;
    if (!rlc_have_leaf(spec, "b/c/d: verified launch, fd-3 frame protocol, "
                       "observable result"))
        return 1;
    struct rlc_call c;
    rlc_call_package(&c, spec, datadir, root_hex, receipt_hex, sha3_hex,
                     RLC_ZTASKS_PROGRAM, "list");
    bool ran = rlc_invoke(&c);
    if (ran && !rlc_ok(&c))
        printf("[invocation refused: code=%s message=%s] ",
               c.reply.error.code, c.reply.error.message);
    RLC_CHECK("stage b: the launch verified the mapped image (accepted "
              "digest + mapped proof + launch nonce in the receipt)",
              ran && rlc_ok(&c) &&
              strcmp(rlc_str(&c, "artifact_sha3"), sha3_hex) == 0 &&
              (strcmp(rlc_str(&c, "mapped_proof"), "fexecve_inode") == 0 ||
               strcmp(rlc_str(&c, "mapped_proof"), "proc_exe_triple") == 0 ||
               strcmp(rlc_str(&c, "mapped_proof"), "cdhash_suspended") == 0) &&
              rlc_hex64(rlc_str(&c, "nonce")) &&
              rlc_int(&c, "start_token") > 0);
    RLC_CHECK("stage c: the child spoke z23-res-run-v1 on fd 3 (READY gate "
              "+ one bounded frame round-trip: empty list renders exactly)",
              ran && rlc_ok(&c) &&
              strcmp(rlc_str(&c, "result"), "No tasks yet.\n") == 0);
    RLC_CHECK("stage d: the result is observable through the product reply "
              "(payload + resident pid + bounded timings + reaped child)",
              ran && rlc_ok(&c) && rlc_str(&c, "result")[0] &&
              strcmp(rlc_str(&c, "program"), RLC_ZTASKS_PROGRAM) == 0 &&
              rlc_int(&c, "pid") > 0 &&
              rlc_int(&c, "verification_us") >= 0 &&
              rlc_int(&c, "first_result_us") >= 0 &&
              rlc_int(&c, "completed_us") >= 0 &&
              rlc_bool(&c, "child_reaped") &&
              rlc_str(&c, "next_action")[0]);
    if (ran && rlc_ok(&c))
        printf("resident_launch_contract: invocation timings "
               "verification_us=%lld first_result_us=%lld "
               "completed_us=%lld mapped_proof=%s "
               "artifact_sha3=%s package_root=%s receipt_id=%s "
               "pid=%lld start_token=%lld nonce=%s\n",
               rlc_int(&c, "verification_us"),
               rlc_int(&c, "first_result_us"),
               rlc_int(&c, "completed_us"), rlc_str(&c, "mapped_proof"),
               rlc_str(&c, "artifact_sha3"), root_hex, receipt_hex,
               rlc_int(&c, "pid"), rlc_int(&c, "start_token"),
               rlc_str(&c, "nonce"));
    rlc_end(&c);

    /* A second explicit one-shot: state is per-invocation by design, so
     * "add" renders exactly its own fresh state. */
    struct rlc_call add;
    rlc_call_package(&add, spec, datadir, root_hex, receipt_hex, sha3_hex,
                     RLC_ZTASKS_PROGRAM, "add ship the consumer");
    bool ran_add = rlc_invoke(&add);
    RLC_CHECK("stage d: a second bounded invocation returns its own exact "
              "render (no hidden cross-invocation state)",
              ran_add && rlc_ok(&add) &&
              strcmp(rlc_str(&add, "result"),
                     "1 [OPEN] ship the consumer\n") == 0);
    rlc_end(&add);
    return failures;
}

/* ── stage f labeled greens: exactly what C's one-shot slice proves ──────
 * C's bounded invocation never mutates package state, so a failed
 * candidate leaves every installed receipt bit-identical — proven by
 * re-deriving the accepted artifact from the installed receipt and by an
 * EXPLICIT re-invocation naming the same receipt. Labeled for exactly
 * what it is: operator re-invocation, NOT rollback proof (C's own
 * warning: rerunning a prior root is not atomic rollback proof). */
static int rlc_stage_f_labeled(const struct zcl_command_spec *spec,
                               const char *datadir, const char *root_hex,
                               const char *receipt_hex, const char *sha3_hex)
{
    int failures = 0;
    uint8_t root_bin[32], receipt_bin[32];
    bool bound = zcl_hex_decode_lower(root_hex, root_bin, 32) &&
                 zcl_hex_decode_lower(receipt_hex, receipt_bin, 32);
    struct package_resident_artifact artifact;
    struct zcl_result ar = bound
        ? package_resident_artifact_read(datadir, root_bin, receipt_bin,
                                         RLC_ZTASKS_PROGRAM, &artifact)
        : ZCL_ERR(-1, "fixture hex");
    RLC_CHECK("stage f (labeled): a failed candidate changes no installed "
              "receipt — the accepted artifact re-derives from product "
              "state with the same digest (NOT rollback proof)",
              bound && ar.ok &&
              strcmp(artifact.accepted.image_sha3_hex, sha3_hex) == 0);
    struct rlc_call again;
    rlc_call_package(&again, spec, datadir, root_hex, receipt_hex, sha3_hex,
                     RLC_ZTASKS_PROGRAM, "list");
    bool ran_again = rlc_invoke(&again);
    RLC_CHECK("stage f (labeled): the prior receipt still explicitly "
              "invokes after the failed candidate (operator re-invocation, "
              "NOT rollback proof)",
              ran_again && rlc_ok(&again) &&
              strcmp(rlc_str(&again, "result"), "No tasks yet.\n") == 0);
    rlc_end(&again);
    return failures;
}

/* ── stage f TRAP: the serving-generation acceptance sequence ────────────
 * The independent finish line for C's coming implementation, born-RED
 * today: every check drives the product leaf handler under the stage-f
 * contract of the ADAPTER SEAM and FAILS with a message naming the
 * missing product behavior. The sequence is the owner directive of
 * 2026-09-15:
 *   f1 N accepted as pending candidate (serving record as product state)
 *   f2 N activated → the authoritative serving generation
 *   f3 N+1 becomes READY through the fd3 gate BEFORE any switch
 *   f4 atomic switch N → N+1 (no double-serving window observable)
 *   f5 a late/stale N invocation after the switch cannot regain authority
 *   f6 rapid N+2 supersedes a pending N+1 (obsolete candidate reaped),
 *      then the successor explicitly activates into serving — an accept
 *      alone can never switch serving (f3), so without this activate f7
 *      could not legitimately expect N+2 serving (sequencing correction
 *      per C review)
 *   f7 a VALID pending candidate is accepted, then its activate re-proof
 *      fails after its install locator becomes unavailable: the serving
 *      generation is untouched, evidence naming its digest — a genuine
 *      reproof failure, never a refusal of a malformed identifier
 *      (correction per C review). Accept itself probes through the fd3
 *      gate, so a candidate that never answers can never become pending;
 *      the failure must be injected between accept and activate.
 *   f8 rollback: A serving → B accepted → B activated → forced B failure
 *      → EXACT A restored (same 64-hex digest) → A produces a valid result
 *   f9 restart: the same authoritative generation still serves (the
 *      record lives in product state, never process memory)
 * n, n1, n2, b are the installed ztasks generations 0.2.0/0.3.0/0.4.0/
 * 0.5.0. The separate stage-e parker still proves bounded cancellation. */

/* Accept the named candidate through the serving gate, leaving the call
 * open for reply inspection; the caller ends it. */
static bool rlc_accept(struct rlc_call *c,
                       const struct zcl_command_spec *spec,
                       const char *datadir, const struct rlc_binding *cand)
{
    rlc_call_serving(c, spec, datadir, RLC_APP, "accept",
                     cand->root_hex, cand->receipt_hex, cand->sha3,
                     RLC_ZTASKS_PROGRAM, "list");
    return rlc_invoke(c) && rlc_ok(c);
}

/* f6/f7 shared plumbing, extracted to keep rlc_stage_f_trap under the
 * shrink-only cyclomatic-complexity ratchet: activate the pending
 * candidate, then prove the serving invoke answers the wanted exact
 * digest and render. */
static bool rlc_activate_pending_and_verify(const struct zcl_command_spec *spec,
                                            const char *datadir,
                                            const struct rlc_binding *want,
                                            long long want_generation,
                                            const char *want_result)
{
    struct rlc_call act, inv;
    rlc_call_serving(&act, spec, datadir, RLC_APP, "activate",
                     NULL, NULL, NULL, NULL, "list");
    bool ran_act = rlc_invoke(&act);
    rlc_call_serving(&inv, spec, datadir, RLC_APP, "invoke",
                     NULL, NULL, NULL, NULL, "list");
    bool ran_inv = rlc_invoke(&inv);
    bool ok = ran_act && rlc_ok(&act) &&
              strcmp(rlc_str(&act, "serving_sha3"), want->sha3) == 0 &&
              rlc_int(&act, "generation") == want_generation &&
              ran_inv && rlc_ok(&inv) &&
              strcmp(rlc_str(&inv, "artifact_sha3"), want->sha3) == 0 &&
              strcmp(rlc_str(&inv, "result"), want_result) == 0;
    rlc_end(&act);
    rlc_end(&inv);
    return ok;
}

/* Prove the serving invoke still answers the wanted exact digest and
 * render (the untouched-serving half of failure containment). */
static bool rlc_serving_answers(const struct zcl_command_spec *spec,
                                const char *datadir,
                                const struct rlc_binding *want,
                                const char *want_result)
{
    struct rlc_call inv;
    rlc_call_serving(&inv, spec, datadir, RLC_APP, "invoke",
                     NULL, NULL, NULL, NULL, "list");
    bool ran = rlc_invoke(&inv);
    bool ok = ran && rlc_ok(&inv) &&
              strcmp(rlc_str(&inv, "artifact_sha3"), want->sha3) == 0 &&
              strcmp(rlc_str(&inv, "result"), want_result) == 0;
    rlc_end(&inv);
    return ok;
}

static bool rlc_failed_activation_isolated(const struct zcl_command_spec *spec,
    const char *datadir, const struct rlc_binding *n, const struct rlc_binding *n2)
{
    struct rlc_call acc_bad, act_bad;
    rlc_call_serving(&acc_bad, spec, datadir, RLC_APP, "accept",
                     n->root_hex, n->receipt_hex, n->sha3,
                     RLC_ZTASKS_PROGRAM, "list");
    bool ran_acc_bad = rlc_invoke(&acc_bad);
    bool withheld = ran_acc_bad && rlc_ok(&acc_bad) &&
                    rlc_candidate_locator(datadir, n->root_hex, false);
    rlc_call_serving(&act_bad, spec, datadir, RLC_APP, "activate",
                     NULL, NULL, NULL, NULL, "list");
    bool ran = rlc_invoke(&act_bad);
    bool restored = withheld && rlc_candidate_locator(datadir, n->root_hex, true);
    bool ok = ran_acc_bad && rlc_ok(&acc_bad) && withheld && restored &&
              ran && !rlc_ok(&act_bad) &&
              strstr(act_bad.reply.error.evidence, n2->sha3) != NULL &&
              rlc_serving_answers(spec, datadir, n2,
                                  "No tasks yet (0.4.0).\n");
    rlc_end(&acc_bad);
    rlc_end(&act_bad);
    return ok;
}

static int rlc_stage_f_trap(const struct zcl_command_spec *spec,
                            const char *datadir,
                            const struct rlc_binding *n,
                            const struct rlc_binding *n1,
                            const struct rlc_binding *n2,
                            const struct rlc_binding *b)
{
    int failures = 0;
    if (!rlc_have_leaf(spec, "f: serving-generation supersession + atomic "
                       "rollback"))
        return 1;
    bool ran;

    /* f1 — accept N as the pending candidate. */
    struct rlc_call acc_n;
    rlc_call_serving(&acc_n, spec, datadir, RLC_APP, "accept",
                     n->root_hex, n->receipt_hex, n->sha3,
                     RLC_ZTASKS_PROGRAM, "list");
    ran = rlc_invoke(&acc_n);
    printf("resident_launch_contract: TRAP f1 born-RED — serving generation "
           "record absent: '" RLC_LEAF "' declares no app/action keys, so "
           "the consumer owns no per-app authoritative serving record in "
           "product state\n");
    RLC_CHECK("stage f trap 1: accept admits N as the pending candidate "
              "through the fd3 READY+probe gate and records it (MISSING: "
              "serving generation record)",
              ran && rlc_ok(&acc_n) &&
              strcmp(rlc_str(&acc_n, "pending_sha3"), n->sha3) == 0 &&
              strcmp(rlc_str(&acc_n, "pending_receipt_id"),
                     n->receipt_hex) == 0 &&
              rlc_hex64(rlc_str(&acc_n, "candidate_nonce")) &&
              rlc_int(&acc_n, "candidate_start_token") > 0 &&
              rlc_int(&acc_n, "generation") >= 0);
    rlc_end(&acc_n);

    /* f2 — activate N: the authoritative serving generation answers. */
    struct rlc_call act_n, inv_n;
    rlc_call_serving(&act_n, spec, datadir, RLC_APP, "activate",
                     NULL, NULL, NULL, NULL, "list");
    ran = rlc_invoke(&act_n);
    rlc_call_serving(&inv_n, spec, datadir, RLC_APP, "invoke",
                     NULL, NULL, NULL, NULL, "list");
    bool ran_inv_n = rlc_invoke(&inv_n);
    printf("resident_launch_contract: TRAP f2 born-RED — authoritative "
           "activation unwired: no atomic 'activate' action exists, so no "
           "installed receipt can become the serving generation\n");
    RLC_CHECK("stage f trap 2: activate installs N as the authoritative "
              "serving generation and a serving invoke answers N's exact "
              "digest (MISSING: authoritative serving record + activate)",
              ran && rlc_ok(&act_n) &&
              strcmp(rlc_str(&act_n, "serving_sha3"), n->sha3) == 0 &&
              strcmp(rlc_str(&act_n, "serving_receipt_id"),
                     n->receipt_hex) == 0 &&
              rlc_int(&act_n, "generation") == 1 &&
              ran_inv_n && rlc_ok(&inv_n) &&
              strcmp(rlc_str(&inv_n, "artifact_sha3"), n->sha3) == 0 &&
              strcmp(rlc_str(&inv_n, "result"), "No tasks yet.\n") == 0);
    rlc_end(&act_n);
    rlc_end(&inv_n);

    /* f3 — N+1 becomes READY through the fd3 gate BEFORE any switch. */
    struct rlc_call acc_n1, inv_pre;
    rlc_call_serving(&acc_n1, spec, datadir, RLC_APP, "accept",
                     n1->root_hex, n1->receipt_hex, n1->sha3,
                     RLC_ZTASKS_PROGRAM, "list");
    ran = rlc_invoke(&acc_n1);
    rlc_call_serving(&inv_pre, spec, datadir, RLC_APP, "invoke",
                     NULL, NULL, NULL, NULL, "list");
    bool ran_pre = rlc_invoke(&inv_pre);
    printf("resident_launch_contract: TRAP f3 born-RED — candidate "
           "acceptance unwired: no pending-candidate state exists in which "
           "N+1 can pass the fd3 READY gate while N keeps serving\n");
    RLC_CHECK("stage f trap 3: N+1 becomes READY through the fd3 gate "
              "BEFORE any switch — accepted as pending while the serving "
              "invoke still answers N (MISSING: candidate acceptance "
              "before switch)",
              ran && rlc_ok(&acc_n1) &&
              strcmp(rlc_str(&acc_n1, "pending_sha3"), n1->sha3) == 0 &&
              rlc_hex64(rlc_str(&acc_n1, "candidate_nonce")) &&
              rlc_int(&acc_n1, "candidate_start_token") > 0 &&
              ran_pre && rlc_ok(&inv_pre) &&
              strcmp(rlc_str(&inv_pre, "artifact_sha3"), n->sha3) == 0 &&
              strcmp(rlc_str(&inv_pre, "result"), "No tasks yet.\n") == 0);
    rlc_end(&acc_n1);
    rlc_end(&inv_pre);

    /* f4 — atomic switch N → N+1: one transition, no double-serving
     * window, the old resident cancelled/reaped. */
    struct rlc_call act_n1, inv_n1;
    rlc_call_serving(&act_n1, spec, datadir, RLC_APP, "activate",
                     NULL, NULL, NULL, NULL, "list");
    ran = rlc_invoke(&act_n1);
    rlc_call_serving(&inv_n1, spec, datadir, RLC_APP, "invoke",
                     NULL, NULL, NULL, NULL, "list");
    bool ran_inv_n1 = rlc_invoke(&inv_n1);
    printf("resident_launch_contract: TRAP f4 born-RED — atomic serving "
           "switch unwired: no single-transition activate with from/to "
           "digests exists, so a double-serving window cannot be "
           "excluded\n");
    RLC_CHECK("stage f trap 4: the switch N → N+1 is atomic — one "
              "transition naming both digests, generation +1, the old "
              "resident reaped, and only N+1 answers afterwards (MISSING: "
              "atomic switch)",
              ran && rlc_ok(&act_n1) &&
              strcmp(rlc_str(&act_n1, "switched_from_sha3"), n->sha3) == 0 &&
              strcmp(rlc_str(&act_n1, "serving_sha3"), n1->sha3) == 0 &&
              rlc_int(&act_n1, "generation") == 2 &&
              rlc_no_children() &&
              ran_inv_n1 && rlc_ok(&inv_n1) &&
              strcmp(rlc_str(&inv_n1, "artifact_sha3"), n1->sha3) == 0 &&
              strcmp(rlc_str(&inv_n1, "result"),
                     "No tasks yet (0.3.0).\n") == 0);
    rlc_end(&act_n1);
    rlc_end(&inv_n1);

    /* f5 — a late/stale N invocation after the switch cannot regain
     * authority: refused by name under the nonce + start_token +
     * generation binding, evidence naming the authoritative digest. */
    struct rlc_call stale, inv_post;
    rlc_call_serving(&stale, spec, datadir, RLC_APP, "invoke",
                     n->root_hex, n->receipt_hex, n->sha3,
                     RLC_ZTASKS_PROGRAM, "list");
    ran = rlc_invoke(&stale);
    rlc_call_serving(&inv_post, spec, datadir, RLC_APP, "invoke",
                     NULL, NULL, NULL, NULL, "list");
    bool ran_post = rlc_invoke(&inv_post);
    printf("resident_launch_contract: TRAP f5 born-RED — stale result "
           "authority refusal unwired: no nonce+start_token+generation "
           "binding rejects an invocation bound to a superseded "
           "generation\n");
    RLC_CHECK("stage f trap 5: a late/stale N invocation after the switch "
              "is refused and cannot regain authority — evidence names the "
              "authoritative serving digest, which keeps serving "
              "(MISSING: stale authority refusal)",
              ran && !rlc_ok(&stale) &&
              strstr(stale.reply.error.evidence, n1->sha3) != NULL &&
              ran_post && rlc_ok(&inv_post) &&
              strcmp(rlc_str(&inv_post, "artifact_sha3"), n1->sha3) == 0);
    rlc_end(&stale);
    rlc_end(&inv_post);

    /* f6 — rapid N+2 supersedes a pending N+1: the obsolete candidate is
     * cancelled/reaped (no leak), N+2 becomes pending, serving untouched.
     * The successor then activates explicitly: per f3 an accept can never
     * switch serving, so f7 may only expect N+2 serving after this
     * activate (sequencing correction per C review). */
    struct rlc_call acc_x, acc_y;
    bool ok_x = rlc_accept(&acc_x, spec, datadir, n);
    bool ok_y = rlc_accept(&acc_y, spec, datadir, n2);
    printf("resident_launch_contract: TRAP f6 born-RED — pending candidate "
           "supersession unwired: a second accept cannot retire the first "
           "pending candidate, so an obsolete candidate would leak\n");
    RLC_CHECK("stage f trap 6: rapid N+2 supersedes a pending N+1 cleanly — "
              "the obsolete candidate is cancelled/reaped, the reply names "
              "the supersession, nothing leaks, and the successor then "
              "activates into serving (MISSING: pending supersession + "
              "successor activate)",
              ok_x && ok_y &&
              strcmp(rlc_str(&acc_y, "pending_sha3"), n2->sha3) == 0 &&
              strcmp(rlc_str(&acc_y, "superseded_sha3"), n->sha3) == 0 &&
              rlc_no_children() &&
              rlc_activate_pending_and_verify(spec, datadir, n2, 3,
                                              "No tasks yet (0.4.0).\n"));
    rlc_end(&acc_x);
    rlc_end(&acc_y);

    /* f7 — first complete READY and the bounded probe for valid N. Keep
     * its bytes intact but move its isolated install locator before fresh
     * activation proof, then restore it after refusal. Accept itself must
     * never bypass the full probe simply to manufacture a pending parker. */
    printf("resident_launch_contract: TRAP f7 born-RED — candidate failure "
           "containment unwired: a failed activation has no still-accepted "
           "serving digest to name and no untouched generation to "
           "preserve\n");
    RLC_CHECK("stage f trap 7: a forced candidate failure leaves the "
              "serving generation untouched and the refusal names its "
              "still-accepted 64-hex digest (MISSING: failure containment "
              "+ evidence)",
              rlc_failed_activation_isolated(spec, datadir, n, n2));

    /* f8 — rollback: A (n2) serving → B accepted → B activated → forced B
     * failure (same-length corruption of the installed bytes) → EXACT A
     * restored: the same 64-hex digest, never equivalent bytes, never a
     * pathname — and A produces a valid result. */
    struct rlc_call acc_b, act_b, inv_broken, roll, inv_a;
    rlc_call_serving(&acc_b, spec, datadir, RLC_APP, "accept",
                     b->root_hex, b->receipt_hex, b->sha3,
                     RLC_ZTASKS_PROGRAM, "list");
    bool ran_acc_b = rlc_invoke(&acc_b);
    rlc_call_serving(&act_b, spec, datadir, RLC_APP, "activate",
                     NULL, NULL, NULL, NULL, "list");
    bool ran_act_b = rlc_invoke(&act_b);
    bool corrupted = rlc_corrupt_installed(datadir, b->root_hex,
                                           RLC_ZTASKS_PROGRAM);
    rlc_call_serving(&inv_broken, spec, datadir, RLC_APP, "invoke",
                     NULL, NULL, NULL, NULL, "list");
    bool ran_broken = rlc_invoke(&inv_broken);
    rlc_call_serving(&roll, spec, datadir, RLC_APP, "rollback",
                     NULL, NULL, NULL, NULL, "list");
    ran = rlc_invoke(&roll);
    rlc_call_serving(&inv_a, spec, datadir, RLC_APP, "invoke",
                     NULL, NULL, NULL, NULL, "list");
    bool ran_a = rlc_invoke(&inv_a);
    printf("resident_launch_contract: TRAP f8 born-RED — atomic rollback "
           "unwired: with no prior-generation record there is no EXACT A "
           "to restore (same 64-hex digest, never equivalent bytes, never "
           "a pathname)\n");
    RLC_CHECK("stage f trap 8: A serving → B accepted → B activated → "
              "forced B failure → EXACT A restored (same 64-hex digest) "
              "→ A produces a valid result (MISSING: atomic rollback)",
              ran_acc_b && rlc_ok(&acc_b) &&
              ran_act_b && rlc_ok(&act_b) && corrupted &&
              ran_broken && !rlc_ok(&inv_broken) &&
              ran && rlc_ok(&roll) &&
              strcmp(rlc_str(&roll, "serving_sha3"), n2->sha3) == 0 &&
              ran_a && rlc_ok(&inv_a) &&
              strcmp(rlc_str(&inv_a, "artifact_sha3"), n2->sha3) == 0 &&
              strcmp(rlc_str(&inv_a, "result"),
                     "No tasks yet (0.4.0).\n") == 0);
    rlc_end(&acc_b);
    rlc_end(&act_b);
    rlc_end(&inv_broken);
    rlc_end(&roll);
    rlc_end(&inv_a);

    /* f9 — restart persistence: the handler carries no cross-call process
     * state, so a serving invoke after a consumer restart can only answer
     * from a record that lives in product state (the datadir). */
    struct rlc_call inv_restart;
    rlc_call_serving(&inv_restart, spec, datadir, RLC_APP, "invoke",
                     NULL, NULL, NULL, NULL, "list");
    ran = rlc_invoke(&inv_restart);
    printf("resident_launch_contract: TRAP f9 born-RED — serving record "
           "persistence unwired: the authoritative generation must live in "
           "product state (the datadir), not process memory, so a "
           "restarted consumer finds the same serving generation\n");
    RLC_CHECK("stage f trap 9: after a consumer restart the same "
              "authoritative serving generation still serves (MISSING: "
              "product-state persistence of the serving record)",
              ran && rlc_ok(&inv_restart) &&
              strcmp(rlc_str(&inv_restart, "artifact_sha3"), n2->sha3) == 0 &&
              strcmp(rlc_str(&inv_restart, "result"),
                     "No tasks yet (0.4.0).\n") == 0);
    rlc_end(&inv_restart);
    return failures;
}


/* Process-death injection is registered only in the forked test consumer.
 * It never changes production code or the SQLite transaction result. */
#define RLC_CRASH_APP "ztasks/crash-proof"
static unsigned rlc_crash_write_target;
static unsigned rlc_crash_writes;
static bool rlc_crash_before_commit;

static void rlc_real_update_crash(void *context, int operation,
    const char *database, const char *table, sqlite3_int64 row)
{
    (void)context; (void)database; (void)row;
    if (operation != SQLITE_UPDATE || strcmp(table, "resident_serving") != 0) return;
    ++rlc_crash_writes;
    if (rlc_crash_writes != rlc_crash_write_target || !rlc_crash_before_commit) return;
    /* The consumer only publishes after READY, useful probe, cancel/reap.
     * Refuse the injection if that real child remains owned or waitable. */
    _exit(rlc_no_children() ? 71 : 74);
}

static int rlc_real_auto_extension(sqlite3 *db, char **error,
                                    const sqlite3_api_routines *api)
{
    (void)error; (void)api;
    const char *filename = sqlite3_db_filename(db, "main");
    const char *leaf = filename ? strrchr(filename, '/') : NULL;
    if (leaf && strcmp(leaf + 1, "resident.db") == 0)
        (void)sqlite3_update_hook(db, rlc_real_update_crash, NULL);
    return SQLITE_OK;
}

static void rlc_real_crash_child(const struct zcl_command_spec *spec,
    const char *datadir, bool rollback, bool before_commit)
{
    rlc_crash_writes = 0;
    rlc_crash_write_target = rollback ? 2u : 1u;
    rlc_crash_before_commit = before_commit;
    /* SQLite's documented auto-extension interface uses this signature
     * erasure. Registration exists only in this disposable child process. */
    if (sqlite3_auto_extension((void (*)(void))rlc_real_auto_extension) != SQLITE_OK)
        _exit(70);
    struct rlc_call call;
    rlc_call_serving(&call, spec, datadir, RLC_CRASH_APP,
                     rollback ? "rollback" : "activate",
                     NULL, NULL, NULL, NULL, "list");
    bool ran = rlc_invoke(&call);
    bool complete = ran && rlc_ok(&call) && rlc_bool(&call, "child_reaped");
    if (!complete || !rlc_no_children() || rlc_crash_writes != rlc_crash_write_target)
        _exit(70);
    /* The handler completed its durable commit and reaped the real native
     * child. Exit without freeing the reply or normal process shutdown. */
    _exit(before_commit ? 75 : 72);
}

static bool rlc_real_crash(const struct zcl_command_spec *spec,
    const char *datadir, bool rollback, bool before_commit)
{
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) rlc_real_crash_child(spec, datadir, rollback, before_commit);
    int status = 0;
    pid_t waited;
    do { waited = waitpid(pid, &status, 0); } while (waited < 0 && errno == EINTR);
    return waited == pid && WIFEXITED(status) &&
        WEXITSTATUS(status) == (before_commit ? 71 : 72);
}

struct rlc_crash_context {
    const struct zcl_command_spec *spec;
    const char *datadir;
    const struct rlc_binding *n, *n1, *n2;
    char nonce_n[65];
    long long token_n;
};

static bool rlc_crash_accept(const struct rlc_crash_context *ctx,
    const struct rlc_binding *binding, int64_t config)
{
    struct rlc_call call;
    rlc_call_serving(&call, ctx->spec, ctx->datadir, RLC_CRASH_APP, "accept",
        binding->root_hex, binding->receipt_hex, binding->sha3, RLC_ZTASKS_PROGRAM, "list");
    (void)json_push_kv_int(&call.input, "configuration_generation", config);
    bool ran = rlc_invoke(&call);
    bool ok = ran && rlc_ok(&call) &&
        strcmp(rlc_str(&call, "pending_sha3"), binding->sha3) == 0 &&
        rlc_bool(&call, "child_reaped");
    rlc_end(&call);
    return ok;
}

static bool rlc_crash_observe(const struct rlc_crash_context *ctx,
    const struct rlc_binding *binding, long long generation, long long config)
{
    struct rlc_call call;
    rlc_call_serving(&call, ctx->spec, ctx->datadir, RLC_CRASH_APP, "invoke",
        NULL, NULL, NULL, NULL, "list");
    bool ran = rlc_invoke(&call);
    bool ok = ran && rlc_ok(&call) &&
        strcmp(rlc_str(&call, "artifact_sha3"), binding->sha3) == 0 &&
        strcmp(rlc_str(&call, "receipt_id"), binding->receipt_hex) == 0 &&
        strcmp(rlc_str(&call, "package_root"), binding->root_hex) == 0 &&
        rlc_int(&call, "generation") == generation &&
        rlc_int(&call, "configuration_generation") == config &&
        rlc_bool(&call, "child_reaped") && rlc_str(&call, "result")[0];
    rlc_end(&call);
    return ok;
}

static bool rlc_crash_activate(struct rlc_crash_context *ctx, bool capture)
{
    struct rlc_call call;
    rlc_call_serving(&call, ctx->spec, ctx->datadir, RLC_CRASH_APP, "activate",
        NULL, NULL, NULL, NULL, "list");
    bool ran = rlc_invoke(&call);
    bool ok = ran && rlc_ok(&call) && rlc_bool(&call, "child_reaped");
    if (ok && capture) {
        (void)snprintf(ctx->nonce_n, sizeof(ctx->nonce_n), "%s", rlc_str(&call, "nonce"));
        ctx->token_n = rlc_int(&call, "start_token");
        ok = rlc_hex64(ctx->nonce_n) && ctx->token_n > 0;
    }
    rlc_end(&call);
    return ok;
}

static bool rlc_crash_stale_child(const struct rlc_crash_context *ctx)
{
    struct rlc_call call;
    rlc_call_serving(&call, ctx->spec, ctx->datadir, RLC_CRASH_APP, "invoke",
        NULL, NULL, NULL, NULL, "list");
    (void)json_push_kv_str(&call.input, "nonce", ctx->nonce_n);
    (void)json_push_kv_int(&call.input, "start_token", ctx->token_n);
    (void)json_push_kv_int(&call.input, "generation", 1);
    bool ran = rlc_invoke(&call);
    bool ok = ran && !rlc_ok(&call) &&
        strstr(call.reply.error.evidence, ctx->n2->sha3) != NULL && rlc_no_children();
    rlc_end(&call);
    return ok;
}

static bool rlc_crash_fresh_process(const struct rlc_crash_context *ctx, bool stale)
{
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        bool ok = stale ? rlc_crash_stale_child(ctx) : rlc_crash_observe(ctx, ctx->n2, 3, 3);
        _exit(ok ? 0 : 1);
    }
    int status = 0;
    pid_t waited;
    do { waited = waitpid(pid, &status, 0); } while (waited < 0 && errno == EINTR);
    return waited == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int rlc_real_activation_crashes(struct rlc_crash_context *ctx)
{
    int failures = 0;
    RLC_CHECK("real crash setup: N completes pending acceptance", rlc_crash_accept(ctx, ctx->n, 1));
    RLC_CHECK("real crash setup: N activates with stored proof", rlc_crash_activate(ctx, true));
    RLC_CHECK("real crash setup: exact N serves", rlc_crash_observe(ctx, ctx->n, 1, 1));
    RLC_CHECK("real crash setup: N+1 passes READY and probe", rlc_crash_accept(ctx, ctx->n1, 2));
    RLC_CHECK("real activation process killed inside serving write before COMMIT",
        rlc_real_crash(ctx->spec, ctx->datadir, false, true));
    RLC_CHECK("activation crash recovery preserves exact N configuration", rlc_crash_observe(ctx, ctx->n, 1, 1));
    RLC_CHECK("real activation process exits after COMMIT", rlc_real_crash(ctx->spec, ctx->datadir, false, false));
    RLC_CHECK("committed activation recovery selects exact N+1 configuration", rlc_crash_observe(ctx, ctx->n1, 2, 2));
    return failures;
}

static int rlc_real_rollback_crashes(struct rlc_crash_context *ctx)
{
    int failures = 0;
    RLC_CHECK("real N+2 passes READY and probe", rlc_crash_accept(ctx, ctx->n2, 3));
    RLC_CHECK("real N+2 explicitly activates", rlc_crash_activate(ctx, false));
    RLC_CHECK("fresh consumer process reconstructs exact N+2", rlc_crash_fresh_process(ctx, false));
    RLC_CHECK("fresh consumer process permanently refuses stale N nonce/token/generation",
        rlc_crash_fresh_process(ctx, true));
    RLC_CHECK("stale refusal preserves exact N+2", rlc_crash_observe(ctx, ctx->n2, 3, 3));
    RLC_CHECK("real rollback process killed inside serving write before COMMIT",
        rlc_real_crash(ctx->spec, ctx->datadir, true, true));
    RLC_CHECK("rollback crash recovery preserves exact N+2 configuration", rlc_crash_observe(ctx, ctx->n2, 3, 3));
    RLC_CHECK("real rollback process exits after COMMIT", rlc_real_crash(ctx->spec, ctx->datadir, true, false));
    RLC_CHECK("committed rollback recovers exact accepted N+1 configuration", rlc_crash_observe(ctx, ctx->n1, 4, 2));
    return failures;
}

static int rlc_stage_f_process_crashes(const struct zcl_command_spec *spec,
    const char *datadir, const struct rlc_binding *n,
    const struct rlc_binding *n1, const struct rlc_binding *n2)
{
    struct rlc_crash_context ctx = {.spec = spec, .datadir = datadir,
        .n = n, .n1 = n1, .n2 = n2};
    int failures = rlc_real_activation_crashes(&ctx);
    failures += rlc_real_rollback_crashes(&ctx);
    return failures;
}

#endif /* !defined(_WIN32) */

/* The fixture zcode datadir must satisfy the production resident-store
 * ancestor-ownership gate: EVERY ancestor owned by us or root and
 * non-group/world-writable (or sticky). The repo's test-tmp tree fails
 * that gate on hosts with a group-writable parent (e.g. a 0775 ~/github),
 * so this fixture roots its datadir in the sticky system temp directory —
 * the same compliant ancestor shape a real datadir gets under a 0700
 * home. The OS reaps the tree; aborted runs never pile into the repo. */
static char *rlc_private_base(char *buf, size_t n)
{
    const char *tmp = getenv("TMPDIR");
    if (!tmp || !tmp[0]) tmp = "/tmp";
    int wrote = snprintf(buf, n, "%s/zcl23-rlc-XXXXXX", tmp);
    if (wrote < 0 || (size_t)wrote >= n || !mkdtemp(buf)) {
        fprintf(stderr, "rlc_private_base: no compliant fixture datadir "
                        "under the system temp directory\n");
        abort();
    }
    return buf;
}

int test_resident_launch_contract(void)
{
    int failures = 0;
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(zcl_command_catalog(), RLC_LEAF, NULL);
#if defined(_WIN32)
    /* No descriptor-bound exec on Windows: the leaf exists, so every run
     * stage must refuse by name there, exactly like resident_launch_prepare. */
    failures += rlc_stage_a(spec);
    if (!rlc_have_leaf(spec, "b–f: platform-refused on Windows, blocked on "
                       "the absent consumer leaf")) {
        failures += 5;
    } else {
        struct rlc_call c;
        rlc_begin(&c, spec);
        (void)json_push_kv_str(&c.input, "datadir", "no-such-datadir");
        (void)json_push_kv_str(&c.input, "package_root",
            "0000000000000000000000000000000000000000000000000000000000000000");
        (void)json_push_kv_str(&c.input, "receipt_id",
            "0000000000000000000000000000000000000000000000000000000000000000");
        (void)json_push_kv_str(&c.input, "artifact_sha3",
            "0000000000000000000000000000000000000000000000000000000000000000");
        (void)json_push_kv_str(&c.input, "program", "bin/x");
        (void)json_push_kv_str(&c.input, "input_text", "list");
        (void)json_push_kv_bool(&c.input, "accept_execution", true);
        bool ran = rlc_invoke(&c);
        RLC_CHECK("stages b–f: Windows refuses the resident launch by name",
                  ran && !rlc_ok(&c) && c.reply.error.code[0]);
        rlc_end(&c);
    }
#else
    const char *child = RLC_FIXTURE_CHILD;
    const char *broken = RLC_FIXTURE_BROKEN;
    RLC_CHECK("the fixture children are built (Makefile order-only "
              "prerequisite, never a skip)",
              rlc_executable(child) && rlc_executable(broken));
    struct resident_launch_accepted child_acc;
    RLC_CHECK("capture the reference child's accepted record",
              rlc_accept_of(child, &child_acc));

    /* The fixture datadir is the zcode lifecycle store the consumer binds
     * its accepted-artifact records from; the reference ELF fixtures
     * themselves live in build/. */
    char base[256];
    rlc_private_base(base, sizeof(base));
    char zcode[4400];
    (void)snprintf(zcode, sizeof(zcode), "%s/zcode", base);
    failures += rlc_fixture_selfcheck(child, &child_acc);
    failures += rlc_stage_a(spec);

    uint8_t ztasks_root[32], ztasks_receipt[32];
    uint8_t parker_root[32], parker_receipt[32];
    char ztasks_sha3[65] = {0}, parker_sha3[65] = {0};
    char ztasks_root_hex[65] = {0}, ztasks_receipt_hex[65] = {0};
    char parker_root_hex[65] = {0}, parker_receipt_hex[65] = {0};
    bool installed =
        rlc_install_fixtures(base, zcode, ztasks_root, ztasks_receipt,
                             ztasks_sha3, parker_root, parker_receipt,
                             parker_sha3);
    RLC_CHECK("stage a (deep): the production lifecycle installed REAL "
              "packages and filed their accepted receipts (product state, "
              "never test scaffolding)",
              installed);
    if (installed) {
        zcl_hex_encode(ztasks_root, 32, ztasks_root_hex);
        zcl_hex_encode(ztasks_receipt, 32, ztasks_receipt_hex);
        zcl_hex_encode(parker_root, 32, parker_root_hex);
        zcl_hex_encode(parker_receipt, 32, parker_receipt_hex);

        struct package_resident_artifact artifact;
        struct zcl_result ar = package_resident_artifact_read(
            base, ztasks_root, ztasks_receipt, RLC_ZTASKS_PROGRAM, &artifact);
        struct stat st;
        RLC_CHECK("stage a: the accepted-artifact record re-derives from the "
                  "installed receipt (receipt-bound digest + locator triple)",
                  ar.ok &&
                  strcmp(artifact.accepted.image_sha3_hex, ztasks_sha3) == 0 &&
                  artifact.accepted.image_size > 0 &&
                  stat(artifact.locator, &st) == 0 &&
                  (st.st_mode & 0111) != 0);

        failures += rlc_stage_run(spec, base, ztasks_root_hex,
                                  ztasks_receipt_hex, ztasks_sha3);

        /* The failed candidate for stages e and f: ONE parker invocation,
         * whose refusal both proves bounded cancel/reap and stands as the
         * failed candidate that rollback would have to recover from. */
        struct rlc_call park;
        rlc_call_package(&park, spec, base, parker_root_hex,
                         parker_receipt_hex, parker_sha3, RLC_PARKER_PROGRAM,
                         "list");
        bool ran_park = rlc_invoke(&park);
        RLC_CHECK("stage e: an unresponsive resident is refused inside the "
                  "consumer's own bounded result wait",
                  ran_park && !rlc_ok(&park));
        if (ran_park && !rlc_ok(&park))
            printf("[bounded refusal: code=%s message=%s] ",
                   park.reply.error.code, park.reply.error.message);
        RLC_CHECK("stage e: cancel reaped the resident — no live or zombie "
                  "child remains (process-level proof; failure replies "
                  "carry no data.pid by design)",
                  ran_park && rlc_no_children());

        failures += rlc_stage_f_labeled(spec, base, ztasks_root_hex,
                                        ztasks_receipt_hex, ztasks_sha3);
        rlc_end(&park);

        /* The trap's generation ladder: three edited ztasks generations
         * (distinct program bytes → distinct artifact digests) installed
         * through the same real lifecycle, playing N+1 / N+2 / B against
         * N (0.2.0). Installed AFTER the labeled greens so stage e's
         * world is untouched; the trap itself is born-RED today. */
        struct rlc_binding n1, n2, b;
        bool variants =
            rlc_install_ztasks_variant(base, zcode, "0.3.0", 3,
                                       "No tasks yet (0.3.0).", RLC_PREVIEW_OK, &n1) &&
            rlc_install_ztasks_variant(base, zcode, "0.4.0", 4,
                                       "No tasks yet (0.4.0).", RLC_PREVIEW_OK, &n2) &&
            rlc_install_ztasks_variant(base, zcode, "0.5.0", 5,
                                       "No tasks yet (0.5.0).", RLC_PREVIEW_OK, &b);
        RLC_CHECK("stage f setup: three edited ztasks generations (N+1, "
                  "N+2, B) install through the real lifecycle with "
                  "distinct artifact digests",
                  variants &&
                  strcmp(n1.sha3, ztasks_sha3) != 0 &&
                  strcmp(n2.sha3, n1.sha3) != 0 &&
                  strcmp(b.sha3, n2.sha3) != 0);
        if (variants) {
            struct rlc_binding n;
            rlc_binding_fill(&n, ztasks_root, ztasks_receipt, ztasks_sha3);
            struct rlc_binding broken;
            rlc_binding_fill(&broken, parker_root, parker_receipt, parker_sha3);
            failures += rlc_task_journey(base, &n, &n1, &n2, &broken);
            failures += rlc_stage_f_trap(spec, base, &n, &n1, &n2, &b);
            failures += rlc_stage_f_process_crashes(spec, base, &n, &n1, &n2);
            failures += rlc_task_preview_latency(base, zcode, &n);
        } else {
            printf("resident_launch_contract: generation variants failed "
                   "to install — the stage-f trap is blocked (counted "
                   "above)\n");
            failures += 9;
        }
    } else {
        printf("resident_launch_contract: fixture install failed — stages "
               "b–f blocked (1 counted failure above)\n");
    }
    test_rm_rf(base);
#endif
    if (!spec || !spec->handler) rlc_explain_absent();
    printf("resident_launch_contract: %s (%d failure(s))\n",
           failures ? "FAIL" : "PASS", failures);
    return failures;
}
