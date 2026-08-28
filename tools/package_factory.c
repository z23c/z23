/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package-factory: the ONE reusable package factory for the C23 Commons.
 * Drives one package directory through the full acceptance journey —
 * gate, prepare, offline digest sign, seal, publish, install + confined
 * build in two independent stores, bit-identical reproduction, self-screened
 * admission, and optional corpus registration — reusing only the existing
 * machinery: lib/vcs package_prepare/release/build/reproduce, the
 * zclassic23 native CLI (zcode package dev/publish/add/verify), and the
 * offline signers (zclassic23-package-sign, zclassic23-package-verify).
 * It adds NO second scheduler, store, transport, or receipt family.
 *
 * Subcommands:
 *   package-factory run --package <dir> --publisher-key-file <keyfile>
 *       --publisher-pubkey <66hex> --store-a <datadirA> --store-b <datadirB>
 *       --report <out.json> [--publisher-sequence N] [--kind human|ai|import]
 *       [--chain-id <id>] [--cutoff-height N] [--cutoff-mtp N]
 *       [--signer-seed-file PATH] [--bin-dir <dir>]
 *       [--register-corpus --census-def corpus/scopes.def]
 *   package-factory pin-dep --package <dir> --dep-name <name>
 *       --dep-root <64hex>
 *   package-factory selftest [--repo <repo>] [--scratch <dir>]
 *       [--bin-dir <dir>]
 *
 * REPRODUCTION STRATEGY (same host, disclosed): the add lifecycle's
 * confined emit build files receipt #1 (quick flag profile); the factory
 * then runs the SAME confined build once more through the candidate proof
 * action with the standard flag profile (warning flags only differ, object
 * bytes are unchanged), compares the two receipts with
 * vcs_package_reproduce_compare (must MATCH: byte-identical output sets),
 * and files the second receipt into the store's receipts dir. Two DISTINCT
 * receipt ids committing byte-identical outputs is the reproduction fact
 * vcs_package_reproduce_scan reports. This is honest same-host evidence —
 * NOT independent-operator reproduction (the report says so).
 *
 * DURABILITY: `zcode network storage_ack` requires the live DHT service;
 * offline it is attempted from each store, the refusal is recorded, and the
 * report carries durable_hosting:"unavailable_offline". No daemon is ever
 * started.
 *
 * The key file is the zclassic23-package-sign format: exactly 32 RAW
 * secp256k1 secret bytes, mode 0600/0400 (generate a throwaway one with
 * `zclassic23-package-sign --generate PATH`). The publisher pubkey is
 * cross-checked against the key before anything is signed.
 */

#define _GNU_SOURCE

#include "base/checked.h"
#include "base/cleanse.h"
#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "json/json.h"
#include "platform/clock.h"
#include "platform/rng.h"
#include "sha3/sha3.h"
#include "vcs/package_build.h"
#include "vcs/package_manifest.h"
#include "vcs/package_prepare.h"
#include "vcs/package_release.h"
#include "vcs/package_reproduce.h"
#include "vcs/package_store.h"
#include "vcs/signed_evidence.h"
#include "vcs/zcode_c23_corpus.h"
#include "vcs/zcode_commons.h"
#include "vcs/zcode_family_admission.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>

#define PF_LOG "package.factory"

#define PF_MAX_STEPS 24u
#define PF_CLI_STDOUT_CAP (8u * 1024u * 1024u)
#define PF_META_MAX_BYTES (1024u * 1024u)
#define PF_ERROR_CAP 256u
#define PF_PATH_CAP 4096u

/* Admission expiry horizon, the census construction (~1 year). */
#define PF_ADMISSION_EXPIRY_BLOCKS UINT64_C(525600)
#define PF_ADMISSION_EXPIRY_MTP_SECONDS INT64_C(31536000)

/* The frozen family-c23.v1 policy root (docs/work/C23_LIVING_COMMONS_V2.md);
 * cross-checked at runtime against vcs_zcode_family_policy_v1_default(). */
#define PF_FAMILY_POLICY_ROOT_HEX \
    "460d650c5be714f27dde287c368eafb781467026a1c06a8215fbe17dc610ea86"

/* Evidence domains, identical to the census driver construction. */
static const char k_domain_author[] = "zcl.zcode.corpus.author_binding.v1";
static const char k_domain_assignment_evidence[] =
    "zcl.zcode.corpus.assignment_evidence.v1";
static const char k_domain_dep_closure[] =
    "zcl.zcode.corpus.dependency_closure.v1";
static const char k_domain_moderation[] = "zcl.zcode.corpus.moderation_set.v1";
static const char k_domain_panel[] = "zcl.zcode.corpus.panel.v1";
static const char k_domain_admission_evidence[] =
    "zcl.zcode.corpus.admission_evidence.v1";
static const char k_domain_license[] = "zcl.zcode.corpus.license.v1";
static const char k_panel_literal[] = "founding-self-screen";

/* ── small helpers ────────────────────────────────────────────────── */

struct buf {
    uint8_t *p;
    size_t len, cap;
};

static void buf_free(struct buf *b)
{
    if (!b) return;
    free(b->p);
    memset(b, 0, sizeof(*b));
}

static bool buf_put(struct buf *b, const void *data, size_t len)
{
    size_t need = 0;
    if (!zcl_size_add(b->len, len, &need))
        LOG_FAIL(PF_LOG, "buffer size overflow");
    if (need > b->cap) {
        size_t next = b->cap ? b->cap : 256u;
        while (next < need) {
            if (!zcl_size_mul(next, 2u, &next))
                LOG_FAIL(PF_LOG, "buffer capacity overflow");
        }
        uint8_t *np = zcl_realloc(b->p, next, "factory.buf");
        if (!np)
            LOG_FAIL(PF_LOG, "buffer realloc to %zu", need);
        b->p = np;
        b->cap = next;
    }
    if (len) memcpy(b->p + b->len, data, len);
    b->len += len;
    return true;
}

static bool buf_put_u64le(struct buf *b, uint64_t v)
{
    uint8_t le[8];
    zcl_write_u64_le(le, v);
    return buf_put(b, le, sizeof(le));
}

static uint64_t now_ms(void)
{
    return (uint64_t)(clock_now_monotonic_ns() / 1000000);
}

static bool root_nonzero(const uint8_t root[32])
{
    uint8_t any = 0;
    for (size_t i = 0; i < 32; i++) any |= root[i];
    return any != 0;
}

static bool root_zero(const uint8_t root[32])
{
    return !root_nonzero(root);
}

static void pf_root_hex(const uint8_t root[32], char out[65])
{
    zcl_hex_encode(root, 32, out);
}

/* Read one bounded regular file (allocates *out; caller frees). */
static bool pf_read_file(const char *path, size_t max_bytes, uint8_t **out,
                         size_t *out_len)
{
    *out = NULL;
    *out_len = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        LOG_ERROR(PF_LOG, "open %s: %s", path, strerror(errno));
        return false;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uint64_t)st.st_size > max_bytes) {
        LOG_ERROR(PF_LOG, "stat %s: not a regular file within %zu bytes",
                  path, max_bytes);
        close(fd);
        return false;
    }
    size_t len = (size_t)st.st_size;
    uint8_t *bytes = zcl_malloc(len ? len : 1u, "factory.read");
    if (!bytes) {
        close(fd);
        LOG_FAIL(PF_LOG, "read alloc %zu for %s", len, path);
    }
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, bytes + off, len - off);
        if (r <= 0) {
            LOG_ERROR(PF_LOG, "read %s: %s", path,
                      r == 0 ? "short file" : strerror(errno));
            free(bytes);
            close(fd);
            return false;
        }
        off += (size_t)r;
    }
    close(fd);
    *out = bytes;
    *out_len = len;
    return true;
}

/* Atomic write: <dest>.pfstmp.<pid> beside the destination, fsync, rename
 * (the lib/vcs revert convention). */
static bool pf_write_atomic(const char *path, const uint8_t *data, size_t len)
{
    size_t cap = strlen(path) + 64u;
    char *tmp = zcl_malloc(cap, "factory.tmp");
    if (!tmp)
        LOG_FAIL(PF_LOG, "tmp path alloc");
    (void)snprintf(tmp, cap, "%s.pfstmp.%ld", path, (long)getpid());
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        LOG_ERROR(PF_LOG, "create %s: %s", tmp, strerror(errno));
        free(tmp);
        return false;
    }
    size_t off = 0;
    bool ok = true;
    while (ok && off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w <= 0) ok = false;
        else off += (size_t)w;
    }
    if (ok && fsync(fd) != 0) ok = false;
    if (close(fd) != 0) ok = false;
    if (ok && rename(tmp, path) != 0) ok = false;
    if (!ok) {
        LOG_ERROR(PF_LOG, "write %s: %s", path, strerror(errno));
        unlink(tmp);
    }
    free(tmp);
    return ok;
}

static bool pf_mkdir_p(const char *path)
{
    char *mutable = strdup(path);
    if (!mutable)
        LOG_FAIL(PF_LOG, "mkdir path dup");
    for (char *p = mutable + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(mutable, 0755) != 0 && errno != EEXIST) {
                LOG_ERROR(PF_LOG, "mkdir %s: %s", mutable, strerror(errno));
                free(mutable);
                return false;
            }
            *p = '/';
        }
    }
    if (mkdir(mutable, 0755) != 0 && errno != EEXIST) {
        LOG_ERROR(PF_LOG, "mkdir %s: %s", mutable, strerror(errno));
        free(mutable);
        return false;
    }
    free(mutable);
    return true;
}

/* ── child process spawn (no shell) ───────────────────────────────── */

/* Spawn argv[0] with argv (NULL-terminated), feeding `input` (may be NULL)
 * to its stdin, capturing up to cap bytes of stdout into out (NUL-added).
 * The child inherits stderr so its logs stay visible. Returns the exit
 * code, or -1 on spawn/pipe failure (logged). */
static int pf_spawn(char *const argv[], const uint8_t *input,
                    size_t input_len, char *out, size_t cap)
{
    int stdin_pipe[2] = {-1, -1};
    int stdout_pipe[2] = {-1, -1};
    if (pipe(stdin_pipe) != 0 || pipe(stdout_pipe) != 0)
        LOG_ERR(PF_LOG, "pipe: %s", strerror(errno));
    pid_t pid = fork();
    if (pid < 0)
        LOG_ERR(PF_LOG, "fork: %s", strerror(errno));
    if (pid == 0) {
        (void)dup2(stdin_pipe[0], STDIN_FILENO);
        (void)dup2(stdout_pipe[1], STDOUT_FILENO);
        close(stdin_pipe[0]);
        close(stdin_pipe[1]);
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        execvp(argv[0], argv);
        fprintf(stderr, "%s: execvp %s: %s\n", PF_LOG, argv[0],
                strerror(errno));
        _exit(127);
    }
    close(stdin_pipe[0]);
    close(stdout_pipe[1]);
    size_t total = 0;
    int status = 0;
    /* Write stdin, then read stdout to EOF. Inputs are bounded well under
     * the pipe buffer only for small payloads; the large ones (publish
     * wires) go through a writer/reader loop that interleaves to avoid
     * a pipe-buffer deadlock. */
    size_t written = 0;
    bool stdin_open = input != NULL;
    if (!stdin_open) close(stdin_pipe[1]);
    for (;;) {
        fd_set rfds, wfds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_SET(stdout_pipe[0], &rfds);
        int maxfd = stdout_pipe[0];
        if (stdin_open) {
            FD_SET(stdin_pipe[1], &wfds);
            if (stdin_pipe[1] > maxfd) maxfd = stdin_pipe[1];
        }
        int ready = select(maxfd + 1, &rfds, &wfds, NULL, NULL);
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (stdin_open && FD_ISSET(stdin_pipe[1], &wfds)) {
            ssize_t w = write(stdin_pipe[1], input + written,
                              input_len - written);
            if (w > 0) {
                written += (size_t)w;
                if (written == input_len) {
                    close(stdin_pipe[1]);
                    stdin_open = false;
                }
            } else if (w < 0 && errno != EINTR) {
                close(stdin_pipe[1]);
                stdin_open = false;
            }
        }
        if (FD_ISSET(stdout_pipe[0], &rfds)) {
            if (total + 1u >= cap) {
                char drain[4096];
                ssize_t r = read(stdout_pipe[0], drain, sizeof(drain));
                if (r <= 0) break;
                continue; /* over cap: drain and truncate */
            }
            ssize_t r = read(stdout_pipe[0], out + total,
                             cap - 1u - total);
            if (r <= 0) break;
            total += (size_t)r;
        }
    }
    if (stdin_open) close(stdin_pipe[1]);
    close(stdout_pipe[0]);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
        ;
    out[total] = '\0';
    if (!WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

/* Spawn the node CLI: <bin_dir>/zclassic23 [extraflag...] <words...>
 * --input=- with `input` on stdin. Parses the zcl.result.v1 envelope;
 * returns true when the envelope parsed and reported ok:true. The parsed
 * document lives in doc_out (caller json_free()s it). */
static bool pf_cli(const char *bin_dir, const char *extra_flag,
                   const char *command_words, const char *input,
                   struct json_value *doc_out, char *error,
                   size_t error_cap)
{
    char bin[PF_PATH_CAP];
    if (snprintf(bin, sizeof(bin), "%s/zclassic23", bin_dir) >=
        (int)sizeof(bin))
        LOG_FAIL(PF_LOG, "binary path overflow");
    /* Split the command path into words. */
    char *words_copy = strdup(command_words);
    if (!words_copy)
        LOG_FAIL(PF_LOG, "command words dup");
    char *argv[16];
    size_t argc = 0;
    argv[argc++] = bin;
    if (extra_flag) argv[argc++] = (char *)extra_flag;
    for (char *tok = strtok(words_copy, " ");
         tok && argc + 2u < sizeof(argv) / sizeof(argv[0]);
         tok = strtok(NULL, " "))
        argv[argc++] = tok;
    argv[argc++] = (char *)"--input=-";
    argv[argc] = NULL;
    char *out = zcl_malloc(PF_CLI_STDOUT_CAP, "factory.cli.out");
    if (!out) {
        free(words_copy);
        LOG_FAIL(PF_LOG, "cli stdout alloc");
    }
    int rc = pf_spawn(argv, (const uint8_t *)input,
                      input ? strlen(input) : 0, out, PF_CLI_STDOUT_CAP);
    free(words_copy);
    if (rc != 0) {
        /* Prefer the structured error body over the raw (truncated) line. */
        struct json_value errdoc;
        json_init(&errdoc);
        bool parsed = json_read(&errdoc, out, strlen(out));
        const char *code = parsed
            ? json_get_str(json_get(json_get(&errdoc, "error"), "code"))
            : NULL;
        const char *msg = parsed
            ? json_get_str(json_get(json_get(&errdoc, "error"), "message"))
            : NULL;
        if (code || msg) {
            (void)snprintf(error, error_cap, "%s exit %d: %s%s%s",
                           command_words, rc, code ? code : "?",
                           msg ? ": " : "", msg ? msg : "");
        } else {
            char *nl = strchr(out, '\n');
            if (nl) *nl = '\0';
            (void)snprintf(error, error_cap, "%s exit %d%s%s", command_words,
                           rc, out[0] ? ": " : "", out);
        }
        json_free(&errdoc);
        LOG_ERROR(PF_LOG, "%s", error);
        free(out);
        return false;
    }
    json_init(doc_out);
    if (!json_read(doc_out, out, strlen(out))) {
        (void)snprintf(error, error_cap, "%s: unparsable reply",
                       command_words);
        LOG_ERROR(PF_LOG, "%s", error);
        free(out);
        return false;
    }
    free(out);
    const struct json_value *okv = json_get(doc_out, "ok");
    if (!okv || !json_get_bool(okv)) {
        const char *code =
            json_get_str(json_get(json_get(doc_out, "error"), "code"));
        const char *msg =
            json_get_str(json_get(json_get(doc_out, "error"), "message"));
        (void)snprintf(error, error_cap, "%s refused: %s%s%s", command_words,
                       code ? code : "?", msg ? ": " : "",
                       msg ? msg : "");
        LOG_ERROR(PF_LOG, "%s", error);
        return false;
    }
    return true;
}

/* Strict structural equality for the small scalar values repeated on every
 * page of a paged reply (hex ids, ints, bools, short strings). */
static bool pf_json_same_value(const struct json_value *a,
                               const struct json_value *b)
{
    if (!a || !b || a->type != b->type)
        return false;
    char ba[2048], bb[2048];
    size_t na = json_write(a, ba, sizeof(ba));
    size_t nb = json_write(b, bb, sizeof(bb));
    return na > 0 && na < sizeof(ba) && na == nb && memcmp(ba, bb, na) == 0;
}

/* Rows per requested page: one plan/commit step row is a few hundred
 * bytes, so 8 stays far below the 8192-byte reply envelope. */
#define PF_STEP_PAGE_ITEMS 8

/* Fetch one zcode CLI reply whose `steps` array may exceed the bounded
 * reply envelope: request small pages and follow _page.next_cursor until
 * the array is reassembled. The merged document keeps the FIRST page's
 * scalar fields and the concatenated steps; its stale first-page `_page`
 * is harmless (no consumer reads it). Fails closed unless every page
 * carries data.steps + data._page, every first-page scalar repeats
 * identically on every later page, pages are contiguous (the requested
 * cursor equals the rows collected so far) and strictly advancing, and the
 * final count equals both _page.total_items and data.step_count when the
 * reply declares one. */
static bool pf_cli_paged_steps(const char *bin_dir,
                               const char *command_words,
                               const char *id_key, const char *id_val,
                               const char *datadir,
                               struct json_value *doc_out, char *error,
                               size_t error_cap)
{
    /* The paged request is a handful of small fields; it must NOT inherit
     * the 8 MiB stdout-cap buffer pf_cli carries for replies — the caller
     * (factory_store_journey) already holds one such frame, and stacking
     * two more overflows the default 8 MiB thread stack. */
    char input[2048];
    size_t cursor = 0, collected = 0;
    bool merged = false;
    for (;;) {
        int n = snprintf(input, sizeof(input),
                         "{\"%s\":\"%s\",\"datadir\":\"%s\",\"max_items\":%u,"
                         "\"cursor\":%zu}",
                         id_key, id_val, datadir,
                         (unsigned)PF_STEP_PAGE_ITEMS, cursor);
        if (n <= 0 || (size_t)n >= sizeof(input)) {
            (void)snprintf(error, error_cap, "%s: paged input overflow",
                           command_words);
            LOG_ERROR(PF_LOG, "%s", error);
            break;
        }
        struct json_value page_doc;
        if (!pf_cli(bin_dir, NULL, command_words, input, &page_doc, error,
                    error_cap))
            break; /* pf_cli already logged */
        const char *why = NULL;
        const struct json_value *pdata = json_get(&page_doc, "data");
        const struct json_value *psteps = json_get(pdata, "steps");
        const struct json_value *ppage = json_get(pdata, "_page");
        if (!pdata || !psteps || psteps->type != JSON_ARR || !ppage ||
            ppage->type != JSON_OBJ) {
            why = "paged reply lacks data.steps or data._page";
        } else if (cursor != collected) {
            why = "paged reply is discontiguous";
        }
        /* Page metadata must be read before page_doc is folded or freed. */
        bool truncated = json_get_bool(json_get(ppage, "truncated"));
        int64_t total = json_get_int(json_get(ppage, "total_items"));
        int64_t next = -1;
        if (!why && truncated) {
            const struct json_value *ncv = json_get(ppage, "next_cursor");
            next = ncv ? json_get_int(ncv) : -1;
        }
        size_t page_rows = psteps ? psteps->num_children : 0;
        if (!why && truncated && (page_rows == 0 || next < 0 ||
                                  (size_t)next <= cursor))
            why = "_page.next_cursor does not advance";
        if (!why && merged) {
            /* Every scalar from the first page must repeat identically. */
            const struct json_value *mdata = json_get(doc_out, "data");
            for (size_t k = 0; k < mdata->num_children && !why; k++) {
                const char *key = mdata->keys[k];
                if (strcmp(key, "steps") == 0 || strcmp(key, "_page") == 0)
                    continue;
                if (!pf_json_same_value(&mdata->children[k],
                                        json_get(pdata, key)))
                    why = "a scalar field changed between pages";
            }
        }
        bool moved = false;
        if (!why && !merged) {
            *doc_out = page_doc; /* ownership moves to the caller's doc */
            merged = true;
            moved = true;
        } else if (!why) {
            struct json_value *msteps = (struct json_value *)json_get(
                json_get(doc_out, "data"), "steps");
            for (size_t i = 0; i < page_rows; i++) {
                struct json_value row;
                json_init(&row);
                json_copy(&row, &psteps->children[i]);
                (void)json_push_back(msteps, &row);
                json_free(&row);
            }
        }
        collected += page_rows;
        if (!why && !truncated) {
            if (total < 0 || (size_t)total != collected)
                why = "final _page.total_items disagrees with the rows";
            const struct json_value *scv =
                json_get(json_get(doc_out, "data"), "step_count");
            if (!why && scv && json_get_int(scv) != (int64_t)collected)
                why = "step_count disagrees with the paged rows";
        }
        if (!moved)
            json_free(&page_doc);
        if (why) {
            (void)snprintf(error, error_cap, "%s: %s", command_words, why);
            LOG_ERROR(PF_LOG, "%s", error);
            break;
        }
        if (!truncated)
            return true;
        cursor = (size_t)next;
    }
    if (merged) {
        json_free(doc_out);
        json_init(doc_out); /* safe for the caller to json_free again */
    }
    return false;
}
static bool pf_signer(const char *bin_dir, const char *mode,
                      const char *digest_hex, const char *key_path,
                      char *out, size_t out_cap, char *error,
                      size_t error_cap)
{
    int fd = open(key_path, O_RDONLY); /* NO cloexec: the child inherits it */
    if (fd < 0) {
        (void)snprintf(error, error_cap, "open key %s: %s", key_path,
                       strerror(errno));
        LOG_ERROR(PF_LOG, "%s", error);
        return false;
    }
    char bin[PF_PATH_CAP], fdstr[16];
    if (snprintf(bin, sizeof(bin), "%s/zclassic23-package-sign", bin_dir) >=
        (int)sizeof(bin) ||
        snprintf(fdstr, sizeof(fdstr), "%d", fd) >= (int)sizeof(fdstr)) {
        close(fd);
        LOG_FAIL(PF_LOG, "signer path overflow");
    }
    char *argv[8];
    size_t argc = 0;
    argv[argc++] = bin;
    argv[argc++] = (char *)mode; /* --public or --sign-digest */
    char *digest_arg = (char *)digest_hex;
    if (digest_hex) argv[argc++] = digest_arg;
    argv[argc++] = (char *)"--key-fd";
    argv[argc++] = fdstr;
    argv[argc] = NULL;
    int rc = pf_spawn(argv, NULL, 0, out, out_cap);
    close(fd);
    if (rc != 0 || !out[0]) {
        (void)snprintf(error, error_cap, "signer %s exit %d", mode, rc);
        LOG_ERROR(PF_LOG, "%s", error);
        return false;
    }
    size_t len = strlen(out);
    while (len && isspace((unsigned char)out[len - 1])) out[--len] = '\0';
    return true;
}

/* ── run report ───────────────────────────────────────────────────── */

struct pf_step {
    const char *name;
    bool ok;
    uint64_t ms;
    char error[PF_ERROR_CAP];
};

struct pf_report {
    struct pf_step steps[PF_MAX_STEPS];
    size_t step_count;
    bool failed;
};

static struct pf_step *pf_step_begin(struct pf_report *rep, const char *name)
{
    if (rep->step_count == PF_MAX_STEPS)
        LOG_NULL(PF_LOG, "step bound %u", PF_MAX_STEPS);
    char *copy = strdup(name);
    if (!copy)
        LOG_NULL(PF_LOG, "step name alloc");
    struct pf_step *s = &rep->steps[rep->step_count++];
    memset(s, 0, sizeof(*s));
    s->name = copy;
    return s;
}

static void pf_step_ok(struct pf_step *s, uint64_t started_ms)
{
    s->ok = true;
    s->ms = now_ms() - started_ms;
}

static bool pf_step_fail(struct pf_report *rep, struct pf_step *s,
                         uint64_t started_ms, const char *error)
{
    s->ok = false;
    s->ms = now_ms() - started_ms;
    (void)snprintf(s->error, sizeof(s->error), "%s", error);
    rep->failed = true;
    LOG_ERROR(PF_LOG, "step %s failed: %s", s->name, s->error);
    return false;
}

/* ── the gate ─────────────────────────────────────────────────────── */

struct gate_info {
    char name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    char semver[VCS_PACKAGE_RELEASE_SEMVER_MAX + 1u];
    char license[VCS_PACKAGE_RELEASE_LICENSE_MAX + 1u];
    struct json_value meta; /* owned zcode-package.json document */
};

static void gate_info_free(struct gate_info *info)
{
    json_free(&info->meta);
}

/* Recursive fixed-layout scan: no symlinks or non-regular files, per-file
 * size under the 64 MiB cap, required layout entries present. */
static bool gate_walk(const char *dir, size_t root_len, bool *has_license,
                      bool *has_readme, bool *has_meta, unsigned *inc_h,
                      unsigned *src_c, unsigned *test_c, char *error,
                      size_t error_cap)
{
    DIR *d = opendir(dir);
    if (!d) {
        (void)snprintf(error, error_cap, "opendir %s: %s", dir,
                       strerror(errno));
        LOG_ERROR(PF_LOG, "%s", error);
        return false;
    }
    bool ok = true;
    struct dirent *ent;
    while (ok && (ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        size_t plen = strlen(dir) + strlen(ent->d_name) + 2u;
        char *path = zcl_malloc(plen, "factory.gate.path");
        if (!path)
            LOG_FAIL(PF_LOG, "gate path alloc");
        (void)snprintf(path, plen, "%s/%s", dir, ent->d_name);
        struct stat st;
        if (lstat(path, &st) != 0) {
            (void)snprintf(error, error_cap, "lstat %s: %s", path,
                           strerror(errno));
            LOG_ERROR(PF_LOG, "%s", error);
            free(path);
            ok = false;
            break;
        }
        if (S_ISLNK(st.st_mode)) {
            (void)snprintf(error, error_cap, "symlink refused: %s", path);
            LOG_ERROR(PF_LOG, "%s", error);
            free(path);
            ok = false;
            break;
        }
        if (S_ISDIR(st.st_mode)) {
            ok = gate_walk(path, root_len, has_license, has_readme, has_meta,
                           inc_h, src_c, test_c, error, error_cap);
            free(path);
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            (void)snprintf(error, error_cap, "non-regular file refused: %s",
                           path);
            LOG_ERROR(PF_LOG, "%s", error);
            free(path);
            ok = false;
            break;
        }
        if ((uint64_t)st.st_size > VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES) {
            (void)snprintf(error, error_cap,
                           "file over the 64 MiB cap: %s", path);
            LOG_ERROR(PF_LOG, "%s", error);
            free(path);
            ok = false;
            break;
        }
        const char *rel = path + root_len;
        size_t rlen = strlen(rel);
        bool is_c = rlen >= 3 && strcmp(rel + rlen - 2, ".c") == 0;
        bool is_h = rlen >= 3 && strcmp(rel + rlen - 2, ".h") == 0;
        if (strcmp(rel, "LICENSE") == 0) *has_license = true;
        else if (strcmp(rel, "README") == 0 || strcmp(rel, "README.md") == 0)
            *has_readme = true;
        else if (strcmp(rel, "zcode-package.json") == 0) *has_meta = true;
        if (strncmp(rel, "include/", 8) == 0 && is_h) (*inc_h)++;
        if (strncmp(rel, "src/", 4) == 0 && is_c) (*src_c)++;
        if (strncmp(rel, "tests/", 6) == 0 && is_c) (*test_c)++;
        free(path);
    }
    closedir(d);
    return ok;
}

static bool gate_check(const char *dir, struct gate_info *info, char *error,
                       size_t error_cap)
{
    bool has_license = false, has_readme = false, has_meta = false;
    unsigned inc_h = 0, src_c = 0, test_c = 0;
    size_t root_len = strlen(dir);
    if (root_len && dir[root_len - 1] == '/') root_len--;
    char *root = zcl_malloc(root_len + 1u, "factory.gate.root");
    if (!root)
        LOG_FAIL(PF_LOG, "gate root alloc");
    memcpy(root, dir, root_len);
    root[root_len] = '\0';
    bool ok = gate_walk(root, root_len + 1u, &has_license, &has_readme,
                        &has_meta, &inc_h, &src_c, &test_c, error,
                        error_cap);
    free(root);
    if (!ok) return false;
    if (!has_license || !has_readme || !has_meta || !inc_h || !src_c ||
        !test_c) {
        (void)snprintf(error, error_cap,
            "fixed layout incomplete: LICENSE=%d README=%d "
            "zcode-package.json=%d include-h=%u src-c=%u tests-c=%u",
            (int)has_license, (int)has_readme, (int)has_meta, inc_h, src_c,
            test_c);
        LOG_ERROR(PF_LOG, "gate: %s", error);
        return false;
    }
    /* zcode-package.json: SPDX allowlist and no placeholder dep roots. */
    size_t plen = strlen(dir) + sizeof("/zcode-package.json");
    char *meta_path = zcl_malloc(plen, "factory.gate.meta");
    if (!meta_path)
        LOG_FAIL(PF_LOG, "meta path alloc");
    (void)snprintf(meta_path, plen, "%s/zcode-package.json", dir);
    uint8_t *bytes = NULL;
    size_t blen = 0;
    ok = pf_read_file(meta_path, PF_META_MAX_BYTES, &bytes, &blen);
    free(meta_path);
    if (!ok) {
        (void)snprintf(error, error_cap, "cannot read zcode-package.json");
        return false;
    }
    json_init(&info->meta);
    if (!json_read(&info->meta, (const char *)bytes, blen)) {
        (void)snprintf(error, error_cap, "zcode-package.json is not JSON");
        LOG_ERROR(PF_LOG, "gate: %s", error);
        free(bytes);
        return false;
    }
    free(bytes);
    const char *name = json_get_str(json_get(&info->meta, "name"));
    const char *semver = json_get_str(json_get(&info->meta, "semver"));
    const char *license = json_get_str(json_get(&info->meta, "license"));
    if (!name || !semver || !license ||
        strlen(name) > VCS_PACKAGE_RELEASE_NAME_MAX ||
        strlen(semver) > VCS_PACKAGE_RELEASE_SEMVER_MAX ||
        strlen(license) > VCS_PACKAGE_RELEASE_LICENSE_MAX) {
        (void)snprintf(error, error_cap,
                       "zcode-package.json needs name/semver/license");
        LOG_ERROR(PF_LOG, "gate: %s", error);
        return false;
    }
    (void)snprintf(info->name, sizeof(info->name), "%s", name);
    (void)snprintf(info->semver, sizeof(info->semver), "%s", semver);
    (void)snprintf(info->license, sizeof(info->license), "%s", license);
    if (!vcs_package_release_license_allowed(license)) {
        (void)snprintf(error, error_cap,
                       "license %s is off the v1 SPDX allowlist", license);
        LOG_ERROR(PF_LOG, "gate: %s", error);
        return false;
    }
    const struct json_value *deps = json_get(&info->meta, "dependencies");
    if (deps && deps->type == JSON_ARR) {
        for (size_t i = 0; i < deps->num_children; i++) {
            const struct json_value *dep = json_at(deps, i);
            const char *dname = json_get_str(json_get(dep, "name"));
            const char *droot = json_get_str(json_get(dep, "root"));
            uint8_t raw[32];
            if (!dname || !droot || strlen(droot) != 64 ||
                !zcl_hex_decode_lower(droot, raw, 32)) {
                (void)snprintf(error, error_cap,
                               "malformed dependency %zu in "
                               "zcode-package.json", i);
                LOG_ERROR(PF_LOG, "gate: %s", error);
                return false;
            }
            if (root_zero(raw)) {
                (void)snprintf(error, error_cap,
                    "dependency-placeholder-root: %s still has the all-zero "
                    "placeholder root (pin it: package-factory pin-dep "
                    "--package <dir> --dep-name %s --dep-root <64hex>)",
                    dname, dname);
                LOG_ERROR(PF_LOG, "gate: %s", error);
                return false;
            }
        }
    }
    return true;
}

/* ── pin-dep ──────────────────────────────────────────────────────── */

/* Byte scanner over JSON text: tracks string state and {} depth. Finds the
 * "dependencies" array, then the object element whose "name" string equals
 * dep_name, then the "root" string INSIDE that same object span. Returns
 * the value span (64 chars) via [val_start, val_end). */
static bool pin_dep_locate(const char *text, size_t len, const char *dep_name,
                           size_t *val_start, size_t *val_end,
                           char *error, size_t error_cap)
{
    /* Locate the "dependencies" array open bracket. */
    size_t arr = SIZE_MAX;
    {
        const char needle[] = "\"dependencies\"";
        size_t nl = sizeof(needle) - 1u;
        for (size_t i = 0; i + nl <= len; i++) {
            if (memcmp(text + i, needle, nl) == 0) {
                size_t j = i + nl;
                while (j < len && (text[j] == ' ' || text[j] == '\t' ||
                                   text[j] == '\n' || text[j] == '\r' ||
                                   text[j] == ':'))
                    j++;
                if (j < len && text[j] == '[') {
                    arr = j;
                    break;
                }
            }
        }
    }
    if (arr == SIZE_MAX) {
        (void)snprintf(error, error_cap, "no dependencies array found");
        LOG_ERROR(PF_LOG, "pin-dep: %s", error);
        return false;
    }
    /* Walk the array elements at depth 1, tracking string state. */
    size_t name_hits = 0;
    size_t i = arr + 1u;
    bool ok = false;
    while (i < len && !ok) {
        /* skip ws and element separators */
        while (i < len && (isspace((unsigned char)text[i]) || text[i] == ','))
            i++;
        if (i >= len) break;
        if (text[i] == ']') break;
        if (text[i] != '{') {
            (void)snprintf(error, error_cap,
                           "dependencies element is not an object");
            LOG_ERROR(PF_LOG, "pin-dep: %s", error);
            return false;
        }
        size_t obj_start = i;
        /* find the matching close brace, string-aware */
        int depth = 0;
        bool in_str = false, esc = false;
        size_t obj_end = SIZE_MAX;
        for (size_t j = obj_start; j < len; j++) {
            char c = text[j];
            if (in_str) {
                if (esc) esc = false;
                else if (c == '\\') esc = true;
                else if (c == '"') in_str = false;
                continue;
            }
            if (c == '"') in_str = true;
            else if (c == '{') depth++;
            else if (c == '}') {
                depth--;
                if (depth == 0) {
                    obj_end = j;
                    break;
                }
            }
        }
        if (obj_end == SIZE_MAX) {
            (void)snprintf(error, error_cap, "unbalanced dependency object");
            LOG_ERROR(PF_LOG, "pin-dep: %s", error);
            return false;
        }
        /* Within [obj_start, obj_end): does a "name" string equal
         * dep_name? Record the "root" value span. Explicit string spans. */
        bool name_match = false;
        size_t root_vs = SIZE_MAX, root_ve = SIZE_MAX;
        size_t j = obj_start;
        while (j < obj_end) {
            if (text[j] != '"') {
                j++;
                continue;
            }
            size_t s0 = ++j;
            bool e = false;
            while (j < obj_end && (text[j] != '"' || e)) {
                if (e) e = false;
                else if (text[j] == '\\') e = true;
                j++;
            }
            size_t s1 = j; /* string content [s0, s1) */
            j++;
            /* key? next non-ws char is ':' */
            size_t k = j;
            while (k < obj_end && isspace((unsigned char)text[k])) k++;
            bool is_key = k < obj_end && text[k] == ':';
            size_t slen = s1 - s0;
            if (is_key && slen == 4 && memcmp(text + s0, "name", 4) == 0) {
                /* value string follows */
                size_t v = k + 1;
                while (v < obj_end && isspace((unsigned char)text[v])) v++;
                if (v < obj_end && text[v] == '"') {
                    size_t v0 = ++v;
                    bool e2 = false;
                    while (v < obj_end && (text[v] != '"' || e2)) {
                        if (e2) e2 = false;
                        else if (text[v] == '\\') e2 = true;
                        v++;
                    }
                    if ((size_t)(v - v0) == strlen(dep_name) &&
                        memcmp(text + v0, dep_name, strlen(dep_name)) == 0)
                        name_match = true;
                }
            } else if (is_key && slen == 4 &&
                       memcmp(text + s0, "root", 4) == 0) {
                size_t v = k + 1;
                while (v < obj_end && isspace((unsigned char)text[v])) v++;
                if (v < obj_end && text[v] == '"') {
                    size_t v0 = ++v;
                    bool e2 = false;
                    while (v < obj_end && (text[v] != '"' || e2)) {
                        if (e2) e2 = false;
                        else if (text[v] == '\\') e2 = true;
                        v++;
                    }
                    root_vs = v0;
                    root_ve = v;
                }
            }
        }
        if (name_match) {
            name_hits++;
            if (root_vs == SIZE_MAX || root_ve - root_vs != 64) {
                (void)snprintf(error, error_cap,
                               "dependency %s has no 64-hex root", dep_name);
                LOG_ERROR(PF_LOG, "pin-dep: %s", error);
                return false;
            }
            *val_start = root_vs;
            *val_end = root_ve;
            ok = true;
        }
        i = obj_end + 1u;
    }
    if (!ok) {
        (void)snprintf(error, error_cap, "no dependency named %s", dep_name);
        LOG_ERROR(PF_LOG, "pin-dep: %s", error);
        return false;
    }
    if (name_hits != 1) {
        (void)snprintf(error, error_cap, "dependency %s is not unique",
                       dep_name);
        LOG_ERROR(PF_LOG, "pin-dep: %s", error);
        return false;
    }
    return true;
}

static int cmd_pin_dep(const char *dir, const char *dep_name,
                       const char *dep_root)
{
    uint8_t raw[32];
    if (!dep_name || !*dep_name || !dep_root || strlen(dep_root) != 64 ||
        !zcl_hex_decode_lower(dep_root, raw, 32) || root_zero(raw))
        LOG_ERR(PF_LOG,
                "pin-dep needs --dep-name <name> and --dep-root <64 "
                "lowercase hex, nonzero>");
    size_t plen = strlen(dir) + sizeof("/zcode-package.json");
    char *path = zcl_malloc(plen, "factory.pindep");
    if (!path)
        LOG_ERR(PF_LOG, "pin-dep path alloc");
    (void)snprintf(path, plen, "%s/zcode-package.json", dir);
    uint8_t *text = NULL;
    size_t len = 0;
    if (!pf_read_file(path, PF_META_MAX_BYTES, &text, &len)) {
        free(path);
        return 1;
    }
    char error[PF_ERROR_CAP];
    size_t vs = 0, ve = 0;
    if (!pin_dep_locate((const char *)text, len, dep_name, &vs, &ve,
                        error, sizeof(error))) {
        free(text);
        free(path);
        return 1;
    }
    /* Refuse unless the current value is the all-zero placeholder. */
    char cur_hex[65];
    memcpy(cur_hex, text + vs, 64);
    cur_hex[64] = '\0';
    uint8_t cur[32];
    if (!zcl_hex_decode_lower(cur_hex, cur, 32) || !root_zero(cur)) {
        LOG_ERROR(PF_LOG,
                  "dependency %s is already pinned (no placeholder); "
                  "refusing to replace a real root", dep_name);
        free(text);
        free(path);
        return 1;
    }
    /* Strict rewrite: same length, only the 64 root chars change. */
    struct buf out = {0};
    if (!buf_put(&out, text, vs) || !buf_put(&out, dep_root, 64) ||
        !buf_put(&out, text + ve, len - ve)) {
        free(text);
        free(path);
        buf_free(&out);
        return 1;
    }
    bool ok = pf_write_atomic(path, out.p, out.len);
    buf_free(&out);
    free(text);
    if (!ok) {
        free(path);
        return 1;
    }
    /* Re-parse the rewritten file and confirm the pin landed exactly. */
    uint8_t *check = NULL;
    size_t clen = 0;
    if (!pf_read_file(path, PF_META_MAX_BYTES, &check, &clen)) {
        free(path);
        return 1;
    }
    struct json_value doc;
    json_init(&doc);
    bool parsed = json_read(&doc, (const char *)check, clen);
    free(check);
    if (!parsed) {
        json_free(&doc);
        LOG_ERROR(PF_LOG, "rewritten %s no longer parses", path);
        free(path);
        return 1;
    }
    const struct json_value *deps = json_get(&doc, "dependencies");
    bool confirmed = false;
    if (deps && deps->type == JSON_ARR) {
        for (size_t i = 0; i < deps->num_children; i++) {
            const struct json_value *dep = json_at(deps, i);
            const char *n = json_get_str(json_get(dep, "name"));
            const char *r = json_get_str(json_get(dep, "root"));
            if (n && r && strcmp(n, dep_name) == 0 &&
                strcmp(r, dep_root) == 0)
                confirmed = true;
        }
    }
    json_free(&doc);
    if (!confirmed) {
        free(path);
        LOG_ERR(PF_LOG, "pin verification failed for %s", dep_name);
    }
    printf("pin-dep: %s dependencies[%s].root = %s\n", path, dep_name,
           dep_root);
    free(path);
    return 0;
}

/* ── admission signing seed (the census signer seed convention) ────── */

static bool pf_seed_load_or_create(const char *path, uint8_t seed[32])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        struct stat st;
        uint8_t raw[32];
        size_t off = 0;
        bool ok = fstat(fd, &st) == 0 && st.st_size == 32;
        while (ok && off < sizeof(raw)) {
            ssize_t r = read(fd, raw + off, sizeof(raw) - off);
            if (r <= 0) ok = false;
            else off += (size_t)r;
        }
        close(fd);
        if (!ok)
            LOG_FAIL(PF_LOG, "signer seed %s must be exactly 32 raw bytes",
                     path);
        memcpy(seed, raw, sizeof(raw));
        memory_cleanse(raw, sizeof(raw));
        return true;
    }
    if (errno != ENOENT)
        LOG_FAIL(PF_LOG, "open signer seed %s: %s", path, strerror(errno));
    const char *slash = strrchr(path, '/');
    if (!slash)
        LOG_FAIL(PF_LOG, "signer seed path %s has no directory", path);
    {
        size_t dir_len = (size_t)(slash - path);
        char *dir = zcl_malloc(dir_len + 1u, "factory.seed.dir");
        if (!dir)
            LOG_FAIL(PF_LOG, "seed dir alloc");
        memcpy(dir, path, dir_len);
        dir[dir_len] = '\0';
        if (!pf_mkdir_p(dir)) {
            free(dir);
            return false;
        }
        free(dir);
    }
    if (!rng_fill(seed, 32))
        LOG_FAIL(PF_LOG, "kernel CSPRNG refused 32 bytes");
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        LOG_FAIL(PF_LOG, "create signer seed %s: %s", path,
                 strerror(errno));
    size_t off = 0;
    bool ok = true;
    while (ok && off < 32) {
        ssize_t w = write(fd, seed + off, 32 - off);
        if (w <= 0) ok = false;
        else off += (size_t)w;
    }
    if (ok && fsync(fd) != 0) ok = false;
    if (close(fd) != 0) ok = false;
    if (!ok)
        LOG_FAIL(PF_LOG, "write signer seed %s: %s", path, strerror(errno));
    LOG_WARN(PF_LOG, "generated NEW factory signer seed at %s (mode 0600, "
             "raw 32 bytes)", path);
    return true;
}

/* ── the run pipeline ─────────────────────────────────────────────── */

struct run_args {
    const char *package_dir;
    const char *key_file;
    const char *publisher_pubkey; /* 66 hex */
    const char *store_a;
    const char *store_b;
    const char *report_path;
    const char *dep_plan_path; /* NULL: no dependency plan emission */
    const char *fast_cache_dir; /* NULL: no per-TU object cache */
    const char *bin_dir;
    const char *census_def;
    const char *signer_seed_file;
    const char *chain_id;
    const char *kind; /* human|ai|import; default ai */
    uint64_t publisher_sequence;
    uint64_t cutoff_height;
    int64_t cutoff_mtp;
    bool register_corpus;
};

struct store_result {
    bool publish_ok;
    bool add_ok;
    bool emit_ok;
    bool verify_ok;
    bool reproduced;
    char plan_id[65];
    char receipt_quick[65];
    char receipt_standard[65];
    char storage_ack_status[64];
};

/* Accumulated per-TU object cache counters (zcl.fastobj.v1) across the
 * run's confined verifier invocations. */
struct pf_fast_stats {
    uint64_t hits;
    uint64_t misses;
    uint64_t reused_bytes;
};

/* Scan verifier stdout for the zbuild-package-fast-cache=v1 summary line
 * and add its counters. Absence is fine (cache disabled on that call). */
static void pf_fast_stats_consume(struct pf_fast_stats *st,
                                  const char *vout)
{
    const char *line = vout;
    while (line && *line) {
        const char *nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);
        unsigned long long h = 0, m = 0, b = 0;
        if (len < 1024 && strstr(line, "zbuild-package-fast-cache=v1") == line &&
            sscanf(line, "zbuild-package-fast-cache=v1 hits=%llu "
                         "misses=%llu reused_bytes=%llu", &h, &m, &b) == 3) {
            st->hits += h;
            st->misses += m;
            st->reused_bytes += b;
        }
        line = nl ? nl + 1 : NULL;
    }
}

/* One confined standard-profile rebuild producing the second, distinct
 * receipt for `store`, compared against the quick-profile install receipt
 * and filed into the store's receipts dir. */
static bool factory_second_receipt(const struct run_args *args,
                                   const char *store,
                                   const char *root_hex,
                                   const char *lock_hex,
                                   const struct json_value *plan_steps,
                                   const uint8_t *recipe_wire,
                                   size_t recipe_wire_len,
                                   const char *reference_receipt_hex,
                                   struct store_result *sr,
                                   struct pf_fast_stats *fast,
                                   char *error, size_t error_cap)
{
    /* Work dir under the system temp, removed at the end. */
    char work[512];
    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir) tmpdir = "/tmp";
    if (snprintf(work, sizeof(work), "%s/package-factory-emit-XXXXXX",
                 tmpdir) >= (int)sizeof(work))
        LOG_FAIL(PF_LOG, "emit work path overflow");
    if (!mkdtemp(work))
        LOG_FAIL(PF_LOG, "mkdtemp under %s: %s", tmpdir, strerror(errno));
    char recipe_path[600], emit_dir[600];
    if (snprintf(recipe_path, sizeof(recipe_path), "%s/recipe.wire", work) >=
            (int)sizeof(recipe_path) ||
        snprintf(emit_dir, sizeof(emit_dir), "%s/emit", work) >=
            (int)sizeof(emit_dir)) {
        LOG_FAIL(PF_LOG, "emit path overflow");
    }
    bool ok = pf_write_atomic(recipe_path, recipe_wire, recipe_wire_len);
    char pkg_abs[PF_PATH_CAP];
    if (ok && !realpath(args->package_dir, pkg_abs)) {
        (void)snprintf(error, error_cap, "realpath %s: %s",
                       args->package_dir, strerror(errno));
        LOG_ERROR(PF_LOG, "%s", error);
        ok = false;
    }
    /* The install receipt is read FIRST: its committed dependency set is
     * the exact, install-time-validated input list the standard-profile
     * rebuild must be fed. The quick path commits the declared DIRECT
     * deps (pkgl_receipt_inputs_match enforces this at install time);
     * the plan's transitive closure is a superset and must NOT be used —
     * the worker records every --dep it is handed, so feeding the closure
     * would mis-record transitive roots and fail reproduction. */
    uint8_t *ref_wire = NULL;
    size_t ref_len = 0;
    struct vcs_package_build_receipt reference;
    if (ok) {
        char ref_path[PF_PATH_CAP];
        if (snprintf(ref_path, sizeof(ref_path), "%s/zcode/receipts/%s",
                     store, reference_receipt_hex) >= (int)sizeof(ref_path))
            LOG_FAIL(PF_LOG, "reference receipt path overflow");
        if (!pf_read_file(ref_path, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES,
                          &ref_wire, &ref_len)) {
            (void)snprintf(error, error_cap,
                           "install receipt %s unreadable",
                           reference_receipt_hex);
            ok = false;
        } else if (vcs_package_build_parse(ref_wire, ref_len, &reference) !=
                       VCS_PACKAGE_BUILD_OK) {
            (void)snprintf(error, error_cap,
                           "install receipt does not parse");
            ok = false;
        }
    }
    int rc = -1;
    if (ok) {
        /* argv: verifier <root> --zbuild-package-source=<abs pkg>
         * --zbuild-package-recipe=<file> --zbuild-package-name=<name>
         * --zbuild-package-profile=standard --zbuild-package-max-cpu-..
         * --emit=<dir> --lock-root=<hex> [--dep=<root>,<dir>]...
         * --require-full-isolation */
        char bin[PF_PATH_CAP];
        if (snprintf(bin, sizeof(bin), "%s/zclassic23-package-verify",
                     args->bin_dir) >= (int)sizeof(bin))
            LOG_FAIL(PF_LOG, "verifier path overflow");
        char source_arg[PF_PATH_CAP + 32], recipe_arg[664],
             emit_arg[664], lock_arg[96];
        static char name_arg[VCS_PACKAGE_RELEASE_NAME_MAX + 32];
        size_t step_count = 0;
        if (plan_steps && plan_steps->type == JSON_ARR)
            step_count = plan_steps->num_children;
        /* Dep argv comes from the reference (install) receipt's committed
         * set — never from the plan's transitive closure (see above). */
        size_t dep_count = reference.dep_count;
        size_t dep_stride = PF_PATH_CAP + 96u;
        char *dep_args = NULL;
        if (dep_count) {
            dep_args = zcl_malloc(dep_stride * dep_count, "factory.depargs");
            if (!dep_args)
                LOG_FAIL(PF_LOG, "dep args alloc");
        }
        if (snprintf(source_arg, sizeof(source_arg),
                     "--zbuild-package-source=%s", pkg_abs) >=
                (int)sizeof(source_arg) ||
            snprintf(recipe_arg, sizeof(recipe_arg),
                     "--zbuild-package-recipe=%s", recipe_path) >=
                (int)sizeof(recipe_arg) ||
            snprintf(emit_arg, sizeof(emit_arg), "--emit=%s", emit_dir) >=
                (int)sizeof(emit_arg) ||
            snprintf(lock_arg, sizeof(lock_arg), "--lock-root=%s",
                     lock_hex) >= (int)sizeof(lock_arg))
            LOG_FAIL(PF_LOG, "verifier arg overflow");
        /* The package name comes from the plan's target step. */
        const char *pkg_name = NULL;
        if (step_count) {
            const struct json_value *target =
                json_at(plan_steps, step_count - 1u);
            pkg_name = json_get_str(json_get(target, "name"));
        }
        if (!pkg_name)
            LOG_FAIL(PF_LOG, "add plan carried no target package name");
        if (snprintf(name_arg, sizeof(name_arg), "--zbuild-package-name=%s",
                     pkg_name) >= (int)sizeof(name_arg))
            LOG_FAIL(PF_LOG, "name arg overflow");
        char fast_arg[PF_PATH_CAP + 16];
        bool use_fast = args->fast_cache_dir != NULL;
        if (use_fast &&
            snprintf(fast_arg, sizeof(fast_arg), "--fast-cache=%s",
                     args->fast_cache_dir) >= (int)sizeof(fast_arg))
            LOG_FAIL(PF_LOG, "fast-cache arg overflow");
        const char *argv[13u + VCS_PACKAGE_BUILD_MAX_DEPS];
        size_t argc = 0;
        argv[argc++] = bin;
        argv[argc++] = root_hex;
        argv[argc++] = source_arg;
        argv[argc++] = recipe_arg;
        argv[argc++] = name_arg;
        argv[argc++] = "--zbuild-package-profile=standard";
        argv[argc++] = "--zbuild-package-max-cpu-seconds=120";
        argv[argc++] = emit_arg;
        argv[argc++] = lock_arg;
        size_t di = 0;
        for (size_t i = 0; i < dep_count; i++) {
            char droot[65];
            pf_root_hex(reference.dep_roots[i], droot);
            size_t need = dep_stride;
            if (snprintf(dep_args + di * dep_stride, need,
                         "--dep=%s,%s/zcode/installed/%s", droot, store,
                         droot) >= (int)need)
                LOG_FAIL(PF_LOG, "dep arg overflow");
            argv[argc++] = dep_args + di * dep_stride;
            di++;
        }
        if (use_fast)
            argv[argc++] = fast_arg;
        argv[argc++] = "--require-full-isolation";
        argv[argc] = NULL;
        char *vout = zcl_malloc(PF_CLI_STDOUT_CAP, "factory.verify.out");
        if (!vout)
            LOG_FAIL(PF_LOG, "verifier stdout alloc");
        rc = pf_spawn((char *const *)argv, NULL, 0, vout, PF_CLI_STDOUT_CAP);
        if (fast)
            pf_fast_stats_consume(fast, vout);
        if (rc != 0) {
            char *nl = strchr(vout, '\n');
            if (nl) *nl = '\0';
            (void)snprintf(error, error_cap,
                           "standard-profile rebuild exit %d%s%s", rc,
                           vout[0] ? ": " : "", vout);
            LOG_ERROR(PF_LOG, "%s", error);
        }
        free(vout);
        free(dep_args);
    }
    if (ok && rc != 0) ok = false;
    /* Read + compare + file the second receipt. */
    if (ok) {
        char report_path[664];
        if (snprintf(report_path, sizeof(report_path), "%s/build-report",
                     emit_dir) >= (int)sizeof(report_path))
            LOG_FAIL(PF_LOG, "report path overflow");
        uint8_t *wire = NULL;
        size_t wire_len = 0;
        if (!pf_read_file(report_path, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES,
                          &wire, &wire_len)) {
            (void)snprintf(error, error_cap, "no build-report emitted");
            ok = false;
        }
        struct vcs_package_build_receipt rebuild;
        if (ok && vcs_package_build_parse(wire, wire_len, &rebuild) !=
                      VCS_PACKAGE_BUILD_OK) {
            (void)snprintf(error, error_cap, "emitted receipt invalid");
            ok = false;
        }
        uint8_t rebuild_id[32];
        if (ok && vcs_package_build_id(&rebuild, rebuild_id) !=
                      VCS_PACKAGE_BUILD_OK) {
            (void)snprintf(error, error_cap, "receipt id failed");
            ok = false;
        }
        /* The reference receipt was read + parsed before the spawn;
         * compare against that pre-validated copy directly. Cleanup is
         * single-point: wire below, ref_wire after this block. */
        if (ok) {
            struct vcs_reproduce_verdict verdict;
            vcs_package_reproduce_compare(&reference, &rebuild,
                                          &verdict);
            if (!verdict.reproduced) {
                (void)snprintf(error, error_cap,
                    "standard-profile rebuild does NOT reproduce the "
                    "install build: %s %s",
                    vcs_reproduce_rule_string(
                        (enum vcs_reproduce_rule)verdict.rule),
                    verdict.detail);
                LOG_ERROR(PF_LOG, "%s", error);
                ok = false;
            } else {
                pf_root_hex(rebuild_id, sr->receipt_standard);
                if (strcmp(sr->receipt_standard,
                           reference_receipt_hex) == 0) {
                    (void)snprintf(error, error_cap,
                        "receipt-not-distinct: the second build filed "
                        "the same receipt id");
                    LOG_ERROR(PF_LOG, "%s", error);
                    ok = false;
                }
            }
        }
        if (ok) {
            char dest[PF_PATH_CAP];
            if (snprintf(dest, sizeof(dest), "%s/zcode/receipts/%s",
                         store, sr->receipt_standard) >=
                (int)sizeof(dest))
                LOG_FAIL(PF_LOG, "receipt dest overflow");
            if (!pf_write_atomic(dest, wire, wire_len)) {
                (void)snprintf(error, error_cap,
                               "cannot file the second receipt");
                ok = false;
            }
        }
        free(wire);
    }
    free(ref_wire);
    /* Best-effort cleanup of the emit work dir. */
    {
        char *rm_argv[] = {(char *)"rm", (char *)"-rf", work, NULL};
        char devnull[16];
        (void)pf_spawn(rm_argv, NULL, 0, devnull, sizeof(devnull));
    }
    if (!ok) return false;
    sr->emit_ok = true;
    return true;
}

/* plan|commit publish + add + second receipt + verify against one store. */
static bool factory_store_journey(const struct run_args *args,
                                  const char *store, const char *release_hex,
                                  const char *manifest_hex,
                                  const char *recipe_hex,
                                  const uint8_t *recipe_wire,
                                  size_t recipe_wire_len,
                                  const char *root_hex,
                                  struct pf_report *rep,
                                  const char *tag,
                                  struct store_result *sr,
                                  struct pf_fast_stats *fast)
{
    /* heap: the manifest wire hex can reach MiBs — never on the stack */
    char *input = zcl_malloc(PF_CLI_STDOUT_CAP, "factory.journey.input");
    if (!input)
        LOG_FAIL(PF_LOG, "store journey input alloc");
    char error[PF_ERROR_CAP];
    struct json_value doc;
    uint64_t t0;

    /* publish plan */
    struct pf_step *s;
    {
        char name[48];
        (void)snprintf(name, sizeof(name), "publish_plan_%s", tag);
        s = pf_step_begin(rep, name);
        t0 = now_ms();
        int n = snprintf(input, PF_CLI_STDOUT_CAP,
            "{\"release_hex\":\"%s\",\"manifest_hex\":\"%s\","
            "\"recipe_hex\":\"%s\",\"dir\":\"%s\",\"datadir\":\"%s\"}",
            release_hex, manifest_hex, recipe_hex, args->package_dir,
            store);
        if (n <= 0 || (size_t)n >= PF_CLI_STDOUT_CAP) {
            (void)pf_step_fail(rep, s, t0, "publish input overflow");
            free(input);
            return false;
        }
        if (!pf_cli(args->bin_dir, NULL, "zcode package publish plan",
                    input, &doc, error, sizeof(error))) {
            (void)pf_step_fail(rep, s, t0, error);
            free(input);
            return false;
        }
        const struct json_value *valid =
            json_get(json_get(&doc, "data"), "valid");
        bool v = valid && json_get_bool(valid);
        if (!v) {
            const struct json_value *data = json_get(&doc, "data");
            const char *readiness =
                json_get_str(json_get(data, "readiness"));
            const char *next_action =
                json_get_str(json_get(data, "next_action"));
            /* The reply carries the exact failed rules; "blocked" alone is
             * undiagnosable from the report, so lead with the first. */
            const struct json_value *failures =
                json_get(data, "failures");
            const char *frule = NULL, *fdetail = NULL;
            if (failures && failures->type == JSON_ARR &&
                failures->num_children) {
                const struct json_value *f0 = &failures->children[0];
                frule = json_get_str(json_get(f0, "rule"));
                fdetail = json_get_str(json_get(f0, "detail"));
            }
            (void)snprintf(error, sizeof(error),
                           "publish plan not valid (readiness=%s next=%s%s%s%s%s)",
                           readiness ? readiness : "?",
                           next_action ? next_action : "?",
                           frule ? " first=" : "", frule ? frule : "",
                           fdetail ? ": " : "", fdetail ? fdetail : "");
        }
        json_free(&doc);
        if (!v) {
            (void)pf_step_fail(rep, s, t0, error);
            free(input);
            return false;
        }
        pf_step_ok(s, t0);
    }
    /* publish commit */
    {
        char name[48];
        (void)snprintf(name, sizeof(name), "publish_commit_%s", tag);
        s = pf_step_begin(rep, name);
        t0 = now_ms();
        int n = snprintf(input, PF_CLI_STDOUT_CAP,
            "{\"release_hex\":\"%s\",\"manifest_hex\":\"%s\","
            "\"recipe_hex\":\"%s\",\"dir\":\"%s\",\"datadir\":\"%s\"}",
            release_hex, manifest_hex, recipe_hex, args->package_dir,
            store);
        if (n <= 0 || (size_t)n >= PF_CLI_STDOUT_CAP) {
            (void)pf_step_fail(rep, s, t0, "publish input overflow");
            free(input);
            return false;
        }
        if (!pf_cli(args->bin_dir, NULL, "zcode package publish commit",
                    input, &doc, error, sizeof(error))) {
            (void)pf_step_fail(rep, s, t0, error);
            free(input);
            return false;
        }
        const char *result =
            json_get_str(json_get(json_get(&doc, "data"), "result"));
        bool okr = result && (strcmp(result, "committed") == 0 ||
                              strcmp(result, "published") == 0 ||
                              strcmp(result, "duplicate") == 0);
        json_free(&doc);
        if (!okr) {
            (void)pf_step_fail(rep, s, t0, "publish commit result bad");
            free(input);
            return false;
        }
        sr->publish_ok = true;
        pf_step_ok(s, t0);
    }
    /* add plan */
    const struct json_value *steps = NULL;
    struct json_value plan_doc;
    json_init(&plan_doc);
    char lock_hex[65] = {0};
    {
        char name[48];
        (void)snprintf(name, sizeof(name), "add_plan_%s", tag);
        s = pf_step_begin(rep, name);
        t0 = now_ms();
        /* A dependency-rich plan overflows the bounded reply envelope, so
         * the fetch pages through the steps array and reassembles it. */
        if (!pf_cli_paged_steps(args->bin_dir, "zcode package add plan",
                                "name_or_root", root_hex, store, &plan_doc,
                                error, sizeof(error))) {
            json_free(&plan_doc);
            (void)pf_step_fail(rep, s, t0, error);
            free(input);
            return false;
        }
        const struct json_value *data = json_get(&plan_doc, "data");
        const char *plan_id = json_get_str(json_get(data, "plan_id"));
        const char *lk = json_get_str(json_get(data, "lock_root"));
        const struct json_value *ready = json_get(data, "ready");
        steps = json_get(data, "steps");
        if (!plan_id || strlen(plan_id) != 64 || !lk || strlen(lk) != 64 ||
            !ready || !json_get_bool(ready) || !steps ||
            steps->type != JSON_ARR || !steps->num_children) {
            json_free(&plan_doc);
            (void)pf_step_fail(rep, s, t0, "add plan not ready");
            free(input);
            return false;
        }
        (void)snprintf(sr->plan_id, sizeof(sr->plan_id), "%s", plan_id);
        (void)snprintf(lock_hex, sizeof(lock_hex), "%s", lk);
        pf_step_ok(s, t0);
    }
    /* add commit */
    {
        char name[48];
        (void)snprintf(name, sizeof(name), "add_commit_%s", tag);
        s = pf_step_begin(rep, name);
        t0 = now_ms();
        /* The commit step list mirrors the plan's, so it can overflow the
         * bounded reply envelope for a dependency-rich plan; page it the
         * same way. */
        if (!pf_cli_paged_steps(args->bin_dir, "zcode package add commit",
                                "plan_id", sr->plan_id, store, &doc, error,
                                sizeof(error))) {
            json_free(&plan_doc);
            (void)pf_step_fail(rep, s, t0, error);
            free(input);
            return false;
        }
        const struct json_value *data = json_get(&doc, "data");
        const struct json_value *inst = json_get(data, "installed");
        const struct json_value *csteps = json_get(data, "steps");
        const char *receipt = NULL;
        if (csteps && csteps->type == JSON_ARR && csteps->num_children) {
            const struct json_value *last =
                json_at(csteps, csteps->num_children - 1u);
            receipt = json_get_str(json_get(last, "build_receipt_id"));
        }
        bool oki = inst && json_get_bool(inst) && receipt &&
                   strlen(receipt) == 64;
        if (oki)
            (void)snprintf(sr->receipt_quick, sizeof(sr->receipt_quick),
                           "%s", receipt);
        json_free(&doc);
        if (!oki) {
            json_free(&plan_doc);
            (void)pf_step_fail(rep, s, t0,
                               "add commit did not install with a "
                               "receipt");
            free(input);
            return false;
        }
        sr->add_ok = true;
        pf_step_ok(s, t0);
    }
    /* second, distinct confined build receipt */
    {
        char name[48];
        (void)snprintf(name, sizeof(name), "reproduce_build_%s", tag);
        s = pf_step_begin(rep, name);
        t0 = now_ms();
        bool ok2 = factory_second_receipt(
            args, store, root_hex, lock_hex, steps, recipe_wire,
            recipe_wire_len, sr->receipt_quick, sr, fast, error,
            sizeof(error));
        json_free(&plan_doc);
        if (!ok2) {
            (void)pf_step_fail(rep, s, t0, error);
            free(input);
            return false;
        }
        pf_step_ok(s, t0);
    }
    /* approved-verifier allowlist (local config; the publisher key) so
     * zcode package verify can run; the quorum is NOT reached without
     * attestations — only the reproduction verdict matters here. */
    {
        char av_path[PF_PATH_CAP];
        if (snprintf(av_path, sizeof(av_path),
                     "%s/zcode/approved_verifiers", store) >=
            (int)sizeof(av_path)) {
            LOG_ERROR(PF_LOG, "approved_verifiers path overflow");
            free(input);
            return false;
        }
        if (access(av_path, R_OK) != 0) {
            char line[70];
            int n = snprintf(line, sizeof(line), "%s\n",
                             args->publisher_pubkey);
            if (n <= 0 ||
                !pf_write_atomic(av_path, (const uint8_t *)line,
                                 (size_t)n)) {
                LOG_ERROR(PF_LOG, "cannot write %s", av_path);
                free(input);
                return false;
            }
        }
    }
    /* verify: require reproduced=true */
    {
        char name[48];
        (void)snprintf(name, sizeof(name), "verify_%s", tag);
        s = pf_step_begin(rep, name);
        t0 = now_ms();
        int n = snprintf(input, PF_CLI_STDOUT_CAP,
                         "{\"root\":\"%s\",\"datadir\":\"%s\"}", root_hex,
                         store);
        if (n <= 0 || (size_t)n >= PF_CLI_STDOUT_CAP) {
            (void)pf_step_fail(rep, s, t0, "verify input overflow");
            free(input);
            return false;
        }
        if (!pf_cli(args->bin_dir, NULL, "zcode package verify", input,
                    &doc, error, sizeof(error))) {
            (void)pf_step_fail(rep, s, t0, error);
            free(input);
            return false;
        }
        const struct json_value *repro = json_get(
            json_get(json_get(&doc, "data"), "reproduction"), "reproduced");
        sr->reproduced = repro && json_get_bool(repro);
        json_free(&doc);
        if (!sr->reproduced) {
            (void)pf_step_fail(rep, s, t0,
                               "reproduction verdict is not reproduced");
            free(input);
            return false;
        }
        sr->verify_ok = true;
        pf_step_ok(s, t0);
    }
    /* storage_ack: attempt plan/commit offline; refusal is expected
     * without the live DHT service and is recorded, never fatal. */
    {
        char name[48];
        (void)snprintf(name, sizeof(name), "storage_ack_%s", tag);
        s = pf_step_begin(rep, name);
        t0 = now_ms();
        char flag[PF_PATH_CAP + 16];
        if (snprintf(flag, sizeof(flag), "-datadir=%s", store) >=
            (int)sizeof(flag)) {
            LOG_ERROR(PF_LOG, "datadir flag overflow");
            free(input);
            return false;
        }
        int n = snprintf(input, PF_CLI_STDOUT_CAP,
            "{\"mode\":\"plan\",\"namespace\":\"commons\","
            "\"transport_root\":\"%s\",\"sequence\":1,\"not_before\":1,"
            "\"expiry\":2}", root_hex);
        if (n <= 0 || (size_t)n >= PF_CLI_STDOUT_CAP) {
            (void)pf_step_fail(rep, s, t0, "storage_ack input overflow");
            free(input);
            return false;
        }
        if (!pf_cli(args->bin_dir, flag, "zcode network storage_ack",
                    input, &doc, error, sizeof(error))) {
            (void)snprintf(sr->storage_ack_status,
                           sizeof(sr->storage_ack_status),
                           "unavailable_offline");
            s->ok = true; /* recorded, not fatal */
            s->ms = now_ms() - t0;
            (void)snprintf(s->error, sizeof(s->error), "%s", error);
        } else {
            const char *token = json_get_str(
                json_get(json_get(&doc, "data"), "plan_token"));
            json_free(&doc);
            bool committed = false;
            if (token && strlen(token) == 64) {
                n = snprintf(input, PF_CLI_STDOUT_CAP,
                    "{\"mode\":\"commit\",\"namespace\":\"commons\","
                    "\"transport_root\":\"%s\",\"sequence\":1,"
                    "\"not_before\":1,\"expiry\":2,\"plan_token\":\"%s\"}",
                    root_hex, token);
                if (n > 0 && (size_t)n < PF_CLI_STDOUT_CAP &&
                    pf_cli(args->bin_dir, flag, "zcode network storage_ack",
                           input, &doc, error, sizeof(error))) {
                    committed = true;
                    json_free(&doc);
                }
            }
            (void)snprintf(sr->storage_ack_status,
                           sizeof(sr->storage_ack_status), "%s",
                           committed ? "committed" : "planned_only");
            pf_step_ok(s, t0);
        }
    }
    free(input);
    return true;
}

/* Emit the exact dependency plan (zcl.dep_plan.v1) for the package: one
 * more confined QUICK-profile build of the same source + recipe through
 * the verifier's --plan mode, with the locked dependency set resolved
 * from store A (whose add journey already installed it). The plan is
 * local evidence filed beside the report — it changes no admission or
 * promotion semantics. On success plan_sha3_out carries the plan file's
 * SHA3-256 hex. */
static bool factory_dep_plan(const struct run_args *args,
                             const char *root_hex,
                             const uint8_t *recipe_wire,
                             size_t recipe_wire_len,
                             char plan_sha3_out[65],
                             struct pf_fast_stats *fast,
                             char *error, size_t error_cap)
{
    plan_sha3_out[0] = '\0';
    char work[512];
    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir) tmpdir = "/tmp";
    if (snprintf(work, sizeof(work), "%s/package-factory-plan-XXXXXX",
                 tmpdir) >= (int)sizeof(work))
        LOG_FAIL(PF_LOG, "plan work path overflow");
    if (!mkdtemp(work))
        LOG_FAIL(PF_LOG, "mkdtemp under %s: %s", tmpdir, strerror(errno));
    char recipe_path[600], emit_dir[600];
    if (snprintf(recipe_path, sizeof(recipe_path), "%s/recipe.wire",
                 work) >= (int)sizeof(recipe_path) ||
        snprintf(emit_dir, sizeof(emit_dir), "%s/emit", work) >=
            (int)sizeof(emit_dir))
        LOG_FAIL(PF_LOG, "plan path overflow");
    bool ok = pf_write_atomic(recipe_path, recipe_wire, recipe_wire_len);
    char pkg_abs[PF_PATH_CAP];
    if (ok && !realpath(args->package_dir, pkg_abs)) {
        (void)snprintf(error, error_cap, "realpath %s: %s",
                       args->package_dir, strerror(errno));
        LOG_ERROR(PF_LOG, "%s", error);
        ok = false;
    }
    /* The locked dependency set comes from store A's add plan — the same
     * resolution the install build used. */
    char lock_hex[65] = {0};
    struct json_value plan_doc;
    json_init(&plan_doc);
    const struct json_value *steps = NULL;
    if (ok) {
        /* A dependency-rich plan overflows the bounded reply envelope, so
         * page through the steps array and reassemble it — same contract
         * the store journey uses. */
        if (!pf_cli_paged_steps(args->bin_dir, "zcode package add plan",
                                "name_or_root", root_hex, args->store_a,
                                &plan_doc, error, error_cap))
            ok = false;
    }
    if (ok) {
        const struct json_value *data = json_get(&plan_doc, "data");
        const char *lk = json_get_str(json_get(data, "lock_root"));
        const struct json_value *ready = json_get(data, "ready");
        steps = json_get(data, "steps");
        if (!lk || strlen(lk) != 64 || !ready || !json_get_bool(ready) ||
            !steps || steps->type != JSON_ARR || !steps->num_children) {
            (void)snprintf(error, error_cap, "add plan not ready");
            ok = false;
        } else {
            (void)snprintf(lock_hex, sizeof(lock_hex), "%s", lk);
        }
    }
    int rc = -1;
    if (ok) {
        /* argv: verifier <root> --zbuild-package-* profile=quick --emit
         * --lock-root [--dep=...]... --plan=<path>
         * --require-full-isolation */
        char bin[PF_PATH_CAP];
        if (snprintf(bin, sizeof(bin), "%s/zclassic23-package-verify",
                     args->bin_dir) >= (int)sizeof(bin))
            LOG_FAIL(PF_LOG, "verifier path overflow");
        char source_arg[PF_PATH_CAP + 32], recipe_arg[664],
             emit_arg[664], lock_arg[96];
        char name_arg[VCS_PACKAGE_RELEASE_NAME_MAX + 32];
        size_t step_count = steps->num_children;
        size_t dep_count = step_count > 1u ? step_count - 1u : 0;
        if (dep_count > VCS_PACKAGE_BUILD_MAX_DEPS)
            LOG_FAIL(PF_LOG, "dep count %zu over the worker bound",
                     dep_count);
        size_t dep_stride = PF_PATH_CAP + 96u;
        char *dep_args = NULL;
        if (dep_count) {
            dep_args = zcl_malloc(dep_stride * dep_count,
                                  "factory.plan.depargs");
            if (!dep_args)
                LOG_FAIL(PF_LOG, "dep args alloc");
        }
        const char *pkg_name = json_get_str(
            json_get(json_at(steps, step_count - 1u), "name"));
        if (!pkg_name)
            LOG_FAIL(PF_LOG, "add plan carried no target package name");
        if (snprintf(source_arg, sizeof(source_arg),
                     "--zbuild-package-source=%s", pkg_abs) >=
                (int)sizeof(source_arg) ||
            snprintf(recipe_arg, sizeof(recipe_arg),
                     "--zbuild-package-recipe=%s", recipe_path) >=
                (int)sizeof(recipe_arg) ||
            snprintf(emit_arg, sizeof(emit_arg), "--emit=%s", emit_dir) >=
                (int)sizeof(emit_arg) ||
            snprintf(lock_arg, sizeof(lock_arg), "--lock-root=%s",
                     lock_hex) >= (int)sizeof(lock_arg) ||
            snprintf(name_arg, sizeof(name_arg), "--zbuild-package-name=%s",
                     pkg_name) >= (int)sizeof(name_arg))
            LOG_FAIL(PF_LOG, "verifier arg overflow");
        char plan_arg[PF_PATH_CAP + 16];
        if (snprintf(plan_arg, sizeof(plan_arg), "--plan=%s",
                     args->dep_plan_path) >= (int)sizeof(plan_arg))
            LOG_FAIL(PF_LOG, "plan arg overflow");
        char fast_arg[PF_PATH_CAP + 16];
        bool use_fast = args->fast_cache_dir != NULL;
        if (use_fast &&
            snprintf(fast_arg, sizeof(fast_arg), "--fast-cache=%s",
                     args->fast_cache_dir) >= (int)sizeof(fast_arg))
            LOG_FAIL(PF_LOG, "fast-cache arg overflow");
        const char *argv[14u + VCS_PACKAGE_BUILD_MAX_DEPS];
        size_t argc = 0;
        argv[argc++] = bin;
        argv[argc++] = root_hex;
        argv[argc++] = source_arg;
        argv[argc++] = recipe_arg;
        argv[argc++] = name_arg;
        argv[argc++] = "--zbuild-package-profile=quick";
        argv[argc++] = "--zbuild-package-max-cpu-seconds=120";
        argv[argc++] = emit_arg;
        argv[argc++] = lock_arg;
        size_t di = 0;
        for (size_t i = 0; i + 1u < step_count; i++) {
            const struct json_value *step = json_at(steps, i);
            const char *droot = json_get_str(json_get(step, "root"));
            if (!droot || strlen(droot) != 64)
                LOG_FAIL(PF_LOG, "add plan step %zu has no root", i);
            if (snprintf(dep_args + di * dep_stride, dep_stride,
                         "--dep=%s,%s/zcode/installed/%s", droot,
                         args->store_a, droot) >= (int)dep_stride)
                LOG_FAIL(PF_LOG, "dep arg overflow");
            argv[argc++] = dep_args + di * dep_stride;
            di++;
        }
        argv[argc++] = plan_arg;
        if (use_fast)
            argv[argc++] = fast_arg;
        argv[argc++] = "--require-full-isolation";
        argv[argc] = NULL;
        char *vout = zcl_malloc(PF_CLI_STDOUT_CAP, "factory.plan.out");
        if (!vout)
            LOG_FAIL(PF_LOG, "verifier stdout alloc");
        rc = pf_spawn((char *const *)argv, NULL, 0, vout,
                      PF_CLI_STDOUT_CAP);
        if (fast)
            pf_fast_stats_consume(fast, vout);
        if (rc != 0) {
            char *nl = strchr(vout, '\n');
            if (nl) *nl = '\0';
            (void)snprintf(error, error_cap,
                           "quick-profile plan build exit %d%s%s", rc,
                           vout[0] ? ": " : "", vout);
            LOG_ERROR(PF_LOG, "%s", error);
        }
        free(vout);
        free(dep_args);
    }
    json_free(&plan_doc);
    if (ok && rc != 0) ok = false;
    /* Hash the emitted plan into the report. */
    if (ok) {
        uint8_t *plan = NULL;
        size_t plan_len = 0;
        if (!pf_read_file(args->dep_plan_path, PF_CLI_STDOUT_CAP, &plan,
                          &plan_len)) {
            (void)snprintf(error, error_cap, "plan %s unreadable",
                           args->dep_plan_path);
            LOG_ERROR(PF_LOG, "%s", error);
            ok = false;
        } else {
            uint8_t digest[32];
            sha3_256(plan, plan_len, digest);
            free(plan);
            zcl_hex_encode(digest, 32, plan_sha3_out);
        }
    }
    /* Best-effort cleanup of the plan work dir. */
    {
        char *rm_argv[] = {(char *)"rm", (char *)"-rf", work, NULL};
        char devnull[16];
        (void)pf_spawn(rm_argv, NULL, 0, devnull, sizeof(devnull));
    }
    return ok;
}

/* Construct and sign the self-screened source_assignment.v1 +
 * commons_admission.v1 for the package — the census driver's
 * construction, with the author binding rooted on the publisher pubkey. */
static bool factory_admission(const struct run_args *args,
                              const struct gate_info *info,
                              const struct vcs_package_prepared *prepared,
                              const uint8_t release_id[32],
                              const uint8_t seed[32],
                              uint8_t admission_root_out[32],
                              uint8_t **admission_wire_out,
                              size_t *admission_wire_len_out,
                              char *error, size_t error_cap)
{
    uint16_t kind = VCS_ZCODE_SOURCE_AI_AUTHORED;
    if (strcmp(args->kind, "human") == 0)
        kind = VCS_ZCODE_SOURCE_HUMAN_AUTHORED;
    else if (strcmp(args->kind, "import") == 0)
        kind = VCS_ZCODE_SOURCE_CANONICAL_IMPORT;

    /* author binding: publisher pubkey hex; assignment evidence: the
     * release id (the factory has no scopes.def line); license: the
     * census license wire over the package LICENSE. */
    uint8_t author_root[32], evidence_root_a[32], license_root[32];
    if (!vcs_signed_evidence_root(k_domain_author, sizeof(k_domain_author),
                                  (const uint8_t *)args->publisher_pubkey,
                                  strlen(args->publisher_pubkey),
                                  author_root) ||
        !vcs_signed_evidence_root(k_domain_assignment_evidence,
                                  sizeof(k_domain_assignment_evidence),
                                  release_id, 32, evidence_root_a))
        LOG_FAIL(PF_LOG, "admission sub-roots failed");
    {
        size_t plen = strlen(args->package_dir) + sizeof("/LICENSE");
        char *lpath = zcl_malloc(plen, "factory.license");
        if (!lpath)
            LOG_FAIL(PF_LOG, "license path alloc");
        (void)snprintf(lpath, plen, "%s/LICENSE", args->package_dir);
        uint8_t *lbytes = NULL;
        size_t llen = 0;
        bool ok = pf_read_file(lpath, PF_META_MAX_BYTES, &lbytes, &llen);
        free(lpath);
        if (!ok) {
            (void)snprintf(error, error_cap, "LICENSE unreadable");
            return false;
        }
        struct buf wire = {0};
        uint8_t digest[32];
        sha3_256(lbytes, llen, digest);
        ok = buf_put(&wire, "LICENSE", sizeof("LICENSE")) &&
             buf_put_u64le(&wire, (uint64_t)llen) &&
             buf_put(&wire, digest, sizeof(digest)) &&
             vcs_signed_evidence_root(k_domain_license,
                                      sizeof(k_domain_license), wire.p,
                                      wire.len, license_root);
        buf_free(&wire);
        free(lbytes);
        if (!ok)
            LOG_FAIL(PF_LOG, "license root failed");
    }

    struct vcs_zcode_source_assignment_v1 assignment;
    memset(&assignment, 0, sizeof(assignment));
    assignment.schema_version = 1;
    assignment.flags = VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS;
    assignment.source_kind = kind;
    assignment.sequence = 1;
    assignment.assigned_height = args->cutoff_height;
    assignment.assigned_mtp = args->cutoff_mtp;
    memcpy(assignment.source_root, prepared->package_root, 32);
    memcpy(assignment.author_binding_root, author_root, 32);
    memcpy(assignment.license_root, license_root, 32);
    memcpy(assignment.assignment_evidence_root, evidence_root_a, 32);
    enum vcs_zcode_c23_error cerr =
        vcs_zcode_source_assignment_v1_sign(&assignment, seed);
    if (cerr != VCS_ZCODE_C23_OK)
        LOG_FAIL(PF_LOG, "assignment sign: %s",
                 vcs_zcode_c23_error_string(cerr));
    uint8_t assignment_root[32];
    cerr = vcs_zcode_source_assignment_v1_root(&assignment, assignment_root);
    if (cerr != VCS_ZCODE_C23_OK)
        LOG_FAIL(PF_LOG, "assignment root: %s",
                 vcs_zcode_c23_error_string(cerr));
    memory_cleanse(&assignment, sizeof(assignment));

    /* dependency closure root: name || NUL || root || NUL || semver || NUL
     * per zcode-package.json dependency (file order), the census recipe. */
    uint8_t dep_closure_root[32];
    {
        struct buf cwire = {0};
        bool ok = true;
        const struct json_value *deps =
            json_get(&((struct gate_info *)info)->meta, "dependencies");
        if (deps && deps->type == JSON_ARR) {
            for (size_t i = 0; ok && i < deps->num_children; i++) {
                const struct json_value *dep = json_at(deps, i);
                const char *n = json_get_str(json_get(dep, "name"));
                const char *r = json_get_str(json_get(dep, "root"));
                const char *v = json_get_str(json_get(dep, "semver"));
                if (!n || !r || !v) {
                    ok = false;
                    break;
                }
                ok = buf_put(&cwire, n, strlen(n) + 1u) &&
                     buf_put(&cwire, r, strlen(r) + 1u) &&
                     buf_put(&cwire, v, strlen(v) + 1u);
            }
        }
        if (ok)
            ok = vcs_signed_evidence_root(k_domain_dep_closure,
                                          sizeof(k_domain_dep_closure),
                                          cwire.p, cwire.len,
                                          dep_closure_root);
        buf_free(&cwire);
        if (!ok)
            LOG_FAIL(PF_LOG, "dependency closure root failed");
    }

    struct vcs_zcode_family_policy_v1 policy;
    vcs_zcode_family_policy_v1_default(&policy);
    uint8_t family_policy_root[32], frozen[32];
    if (vcs_zcode_family_policy_v1_root(&policy, family_policy_root) !=
            VCS_ZCODE_COMMONS_OK ||
        !zcl_hex_decode_lower(PF_FAMILY_POLICY_ROOT_HEX, frozen, 32) ||
        memcmp(family_policy_root, frozen, 32) != 0)
        LOG_FAIL(PF_LOG, "family policy root mismatch with the frozen "
                 "constant");
    uint8_t moderation_root[32], panel_root[32], adm_evidence[32];
    if (!vcs_signed_evidence_root(k_domain_moderation,
                                  sizeof(k_domain_moderation), NULL, 0,
                                  moderation_root) ||
        !vcs_signed_evidence_root(k_domain_panel, sizeof(k_domain_panel),
                                  (const uint8_t *)k_panel_literal,
                                  strlen(k_panel_literal), panel_root) ||
        !vcs_signed_evidence_root(k_domain_admission_evidence,
                                  sizeof(k_domain_admission_evidence),
                                  assignment_root, 32, adm_evidence))
        LOG_FAIL(PF_LOG, "admission sub-roots failed");

    struct vcs_zcode_commons_admission_v1 admission;
    memset(&admission, 0, sizeof(admission));
    admission.schema_version = 1;
    admission.flags = VCS_ZCODE_COMMONS_REQUIRED_FLAGS;
    /* Founding self-screen: tier 0 with the SELF_SCREENED state; zero
     * independent operator groups (disclosed in the report). */
    admission.state = VCS_ZCODE_ADMISSION_SELF_SCREENED;
    admission.tier = VCS_ZCODE_MODERATION_TIER_SELF_SCREENED;
    admission.coverage_complete = 1;
    admission.closure_complete = 1;
    admission.sequence = 1;
    admission.decided_height = args->cutoff_height;
    admission.decided_mtp = args->cutoff_mtp;
    admission.expires_height =
        args->cutoff_height + PF_ADMISSION_EXPIRY_BLOCKS;
    admission.expires_mtp = args->cutoff_mtp + PF_ADMISSION_EXPIRY_MTP_SECONDS;
    memcpy(admission.content_root, prepared->package_root, 32);
    memcpy(admission.dependency_closure_root, dep_closure_root, 32);
    memcpy(admission.family_policy_root, family_policy_root, 32);
    memcpy(admission.moderation_set_root, moderation_root, 32);
    memcpy(admission.panel_root, panel_root, 32);
    memcpy(admission.evidence_root, adm_evidence, 32);
    enum vcs_zcode_family_admission_error aerr =
        vcs_zcode_commons_admission_v1_sign(&admission, seed);
    if (aerr != VCS_ZCODE_FAMILY_ADMISSION_OK)
        LOG_FAIL(PF_LOG, "admission sign: %s",
                 vcs_zcode_family_admission_error_string(aerr));
    aerr = vcs_zcode_commons_admission_v1_root(&admission,
                                               admission_root_out);
    if (aerr != VCS_ZCODE_FAMILY_ADMISSION_OK)
        LOG_FAIL(PF_LOG, "admission root: %s",
                 vcs_zcode_family_admission_error_string(aerr));
    size_t wire_cap = VCS_ZCODE_COMMONS_ADMISSION_WIRE_BYTES;
    uint8_t *wire = zcl_malloc(wire_cap, "factory.admission");
    if (!wire)
        LOG_FAIL(PF_LOG, "admission wire alloc");
    aerr = vcs_zcode_commons_admission_v1_encode(&admission, wire, wire_cap,
                                                 admission_wire_len_out);
    memory_cleanse(&admission, sizeof(admission));
    if (aerr != VCS_ZCODE_FAMILY_ADMISSION_OK) {
        free(wire);
        LOG_FAIL(PF_LOG, "admission encode: %s",
                 vcs_zcode_family_admission_error_string(aerr));
    }
    *admission_wire_out = wire;
    (void)info;
    return true;
}

/* pf_store_label — the committed name of a package store.
 *
 * The factory is handed ABSOLUTE store datadirs (--store-a/--store-b) because
 * it has to read and write them. Nothing it COMMITS may carry that path: the
 * census def line it registers is hashed verbatim into every evidence record,
 * and corpus/factory/<name>.report.json is a tracked file. This repository's
 * privacy rule is that committed files contain no clearnet address, hostname,
 * username, or local filesystem path, and while these two fields held raw
 * datadirs the operator's home directory shipped in all 73 factory reports and
 * all 73 def lines.
 *
 * The label is the store's final path component, which is the part that
 * actually identifies the store; the census resolves it back to a directory
 * through --store-root / $ZCL_CORPUS_STORE_ROOT / $HOME. It must be one path
 * component of [A-Za-z0-9._-], never '.' or '..' — the same predicate
 * store_label_valid() applies in tools/corpus_census.c. Refusing here is what
 * makes the leak unable to recur, rather than relying on a lint gate to catch
 * bytes that were already written.
 *
 * Returns false (with `error` set) when the basename is not label-shaped. */
static bool pf_store_label(const char *store_dir, char *out, size_t out_cap,
                           char *error, size_t error_cap)
{
    if (!store_dir || !*store_dir) {
        (void)snprintf(error, error_cap, "empty store path");
        return false;
    }
    const char *base = strrchr(store_dir, '/');
    base = base ? base + 1 : store_dir;
    /* A trailing slash ("…/store-a/") leaves an empty basename. */
    if (!*base) {
        (void)snprintf(error, error_cap,
                       "store path '%s' ends in '/': name the store "
                       "directory itself", store_dir);
        return false;
    }
    if (strcmp(base, ".") == 0 || strcmp(base, "..") == 0) {
        (void)snprintf(error, error_cap,
                       "store path '%s' has no usable name component",
                       store_dir);
        return false;
    }
    for (const char *p = base; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!(isalnum(c) || c == '.' || c == '_' || c == '-')) {
            (void)snprintf(error, error_cap,
                           "store name '%s' is not label-shaped "
                           "([A-Za-z0-9._-]); the label is committed, so it "
                           "must not need quoting", base);
            return false;
        }
    }
    if (snprintf(out, out_cap, "%s", base) >= (int)out_cap) {
        (void)snprintf(error, error_cap, "store label '%s' too long", base);
        return false;
    }
    return true;
}

/* Idempotent corpus registration: replace the existing `package <name> |`
 * line in the census def, else append. Atomic rewrite.
 *
 * `store_a` arrives as the absolute store datadir; only its LABEL is written
 * (pf_store_label), because the def line is committed and hashed. */
static bool factory_register_corpus(const char *def_path, const char *name,
                                    const char *root_hex, const char *store_a,
                                    const char *kind, const char *spdx,
                                    char *error, size_t error_cap)
{
    uint8_t *text = NULL;
    size_t len = 0;
    bool exists = access(def_path, R_OK) == 0;
    if (exists && !pf_read_file(def_path, 1024u * 1024u, &text, &len)) {
        (void)snprintf(error, error_cap, "cannot read %s", def_path);
        return false;
    }
    char store_label[PF_PATH_CAP];
    if (!pf_store_label(store_a, store_label, sizeof(store_label), error,
                        error_cap)) {
        free(text);
        return false;
    }
    size_t line_cap = strlen(name) + strlen(root_hex) + strlen(store_label) +
                      strlen(kind) + strlen(spdx) + 64u;
    char *line = zcl_malloc(line_cap, "factory.defline");
    if (!line)
        LOG_FAIL(PF_LOG, "def line alloc");
    (void)snprintf(line, line_cap, "package %s | root %s | store %s | "
                   "kind %s | spdx %s", name, root_hex, store_label, kind,
                   spdx);
    struct buf out = {0};
    bool replaced = false;
    bool ok = true;
    size_t pos = 0;
    while (ok && pos < len) {
        size_t eol = pos;
        while (eol < len && text[eol] != '\n') eol++;
        size_t tok_len = strlen("package ");
        if (eol - pos > tok_len + strlen(name) &&
            memcmp(text + pos, "package ", tok_len) == 0 &&
            memcmp(text + pos + tok_len, name, strlen(name)) == 0 &&
            text[pos + tok_len + strlen(name)] == ' ') {
            /* Replace the existing line for this package name. */
            if (replaced) {
                (void)snprintf(error, error_cap,
                               "duplicate package line for %s in %s", name,
                               def_path);
                LOG_ERROR(PF_LOG, "%s", error);
                ok = false;
                break;
            }
            ok = buf_put(&out, line, strlen(line));
            replaced = true;
        } else {
            ok = buf_put(&out, text + pos, eol - pos);
        }
        if (ok && eol < len) ok = buf_put(&out, "\n", 1);
        pos = eol + 1u;
    }
    if (ok && !replaced) {
        if (len && text[len - 1] != '\n') ok = buf_put(&out, "\n", 1);
        if (ok)
            ok = buf_put(&out, line, strlen(line)) &&
                 buf_put(&out, "\n", 1);
    }
    free(line);
    free(text);
    if (!ok) {
        buf_free(&out);
        if (!error[0])
            (void)snprintf(error, error_cap, "def rewrite failed");
        return false;
    }
    if (!pf_write_atomic(def_path, out.p, out.len)) {
        buf_free(&out);
        (void)snprintf(error, error_cap, "cannot write %s", def_path);
        return false;
    }
    buf_free(&out);
    return true;
}

static bool hex_take(char *dst, size_t cap, const uint8_t *src, size_t len)
{
    if (len * 2u + 1u > cap)
        LOG_FAIL(PF_LOG, "hex buffer overflow %zu", len);
    zcl_hex_encode(src, len, dst);
    return true;
}

static int cmd_run(const struct run_args *args)
{
    struct pf_report rep;
    memset(&rep, 0, sizeof(rep));
    char error[PF_ERROR_CAP] = {0};
    struct gate_info info;
    memset(&info, 0, sizeof(info));
    struct vcs_package_prepared prepared;
    bool prepared_ok = false;
    char release_hex[VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES * 2u + 1u];
    char release_id_hex[65] = {0};
    char root_hex_[65] = {0};
    char recipe_root_hex[65] = {0};
    uint8_t release_id[32] = {0};
    uint8_t admission_root[32] = {0};
    uint8_t *admission_wire = NULL;
    size_t admission_wire_len = 0;
    struct store_result sa, sb;
    memset(&sa, 0, sizeof(sa));
    memset(&sb, 0, sizeof(sb));
    struct pf_fast_stats fast_stats;
    memset(&fast_stats, 0, sizeof(fast_stats));
    bool corpus_registered = false;
    char corpus_note[320] = {0};
    uint64_t t_start = now_ms();

    /* 1. GATE */
    struct pf_step *s = pf_step_begin(&rep, "gate");
    uint64_t t0 = now_ms();
    if (gate_check(args->package_dir, &info, error, sizeof(error)))
        pf_step_ok(s, t0);
    else
        (void)pf_step_fail(&rep, s, t0, error);

    /* 2. prepare */
    s = pf_step_begin(&rep, "prepare");
    t0 = now_ms();
    if (!rep.failed) {
        uint8_t pubkey[33];
        if (strlen(args->publisher_pubkey) != 66 ||
            !zcl_hex_decode_lower(args->publisher_pubkey, pubkey, 33)) {
            (void)snprintf(error, sizeof(error),
                           "publisher pubkey must be 66 lowercase hex");
            (void)pf_step_fail(&rep, s, t0, error);
        } else {
            struct vcs_package_prepare_options options = {
                .dir = args->package_dir,
                .reward_address = NULL,
                .chain_id = args->chain_id,
            };
            memcpy(options.publisher_pubkey, pubkey, 33);
            options.publisher_sequence = args->publisher_sequence;
            char detail[256] = {0};
            enum vcs_package_prepare_error perr = vcs_package_prepare(
                &options, &prepared, detail, sizeof(detail));
            if (perr != VCS_PACKAGE_PREPARE_OK) {
                (void)snprintf(error, sizeof(error), "%s: %s",
                               vcs_package_prepare_error_string(perr),
                               detail);
                (void)pf_step_fail(&rep, s, t0, error);
            } else if (strcmp(prepared.release.name, info.name) != 0 ||
                       strcmp(prepared.release.license, info.license) != 0) {
                (void)snprintf(error, sizeof(error),
                               "prepare/metadata name or license mismatch");
                (void)pf_step_fail(&rep, s, t0, error);
                vcs_package_prepared_free(&prepared);
            } else {
                prepared_ok = true;
                pf_root_hex(prepared.package_root, root_hex_);
                pf_root_hex(prepared.recipe_root, recipe_root_hex);
                pf_step_ok(s, t0);
            }
        }
    }

    /* 3. key cross-check + sign the digest offline */
    s = pf_step_begin(&rep, "sign");
    t0 = now_ms();
    char signature_hex[129] = {0};
    if (!rep.failed && prepared_ok) {
        char key_pub[256];
        if (!pf_signer(args->bin_dir, "--public", NULL, args->key_file,
                       key_pub, sizeof(key_pub), error, sizeof(error))) {
            (void)pf_step_fail(&rep, s, t0, error);
        } else if (strcmp(key_pub, args->publisher_pubkey) != 0) {
            (void)pf_step_fail(&rep, s, t0,
                               "publisher-key-file does not match "
                               "--publisher-pubkey");
        } else {
            char digest_hex[65];
            pf_root_hex(prepared.signing_digest, digest_hex);
            if (!pf_signer(args->bin_dir, "--sign-digest", digest_hex,
                           args->key_file, signature_hex,
                           sizeof(signature_hex), error, sizeof(error))) {
                (void)pf_step_fail(&rep, s, t0, error);
            } else if (strlen(signature_hex) != 128) {
                (void)pf_step_fail(&rep, s, t0, "bad signature hex");
            } else {
                pf_step_ok(s, t0);
            }
        }
    }

    /* 4. seal (in-process verification + canonical re-serialization) */
    s = pf_step_begin(&rep, "seal");
    t0 = now_ms();
    uint8_t *release_wire = NULL;
    size_t release_wire_len = 0;
    if (!rep.failed && prepared_ok && signature_hex[0]) {
        uint8_t signature[64];
        bool ok = zcl_hex_decode_lower(signature_hex, signature, 64);
        size_t body_plus = prepared.release_body_len + 64u;
        release_wire = ok ? zcl_malloc(body_plus, "factory.release") : NULL;
        if (!release_wire) {
            (void)pf_step_fail(&rep, s, t0, "release wire alloc/decode");
        } else {
            memcpy(release_wire, prepared.release_body,
                   prepared.release_body_len);
            memcpy(release_wire + prepared.release_body_len, signature, 64);
            release_wire_len = body_plus;
            struct vcs_package_release rel;
            enum vcs_package_release_error rerr =
                vcs_package_release_parse(release_wire, release_wire_len,
                                          &rel);
            if (rerr == VCS_PACKAGE_RELEASE_OK)
                rerr = vcs_package_release_verify(&rel);
            uint8_t *canon = NULL;
            size_t canon_len = 0;
            if (rerr == VCS_PACKAGE_RELEASE_OK)
                rerr = vcs_package_release_id(&rel, release_id);
            if (rerr == VCS_PACKAGE_RELEASE_OK)
                rerr = vcs_package_release_serialize(&rel, &canon,
                                                     &canon_len);
            if (rerr != VCS_PACKAGE_RELEASE_OK ||
                canon_len != release_wire_len ||
                memcmp(canon, release_wire, release_wire_len) != 0) {
                (void)snprintf(error, sizeof(error),
                               "release verification: %s",
                               vcs_package_release_error_string(rerr));
                free(canon);
                (void)pf_step_fail(&rep, s, t0, error);
            } else {
                free(canon);
                hex_take(release_hex, sizeof(release_hex), release_wire,
                         release_wire_len);
                pf_root_hex(release_id, release_id_hex);
                pf_step_ok(s, t0);
            }
        }
    }

    /* 5./6. store A then store B, identical wires */
    if (!rep.failed && prepared_ok && release_wire) {
        char *manifest_hex =
            zcl_malloc(prepared.manifest_wire_len * 2u + 1u,
                       "factory.manifest.hex");
        char *recipe_hex_s =
            zcl_malloc(prepared.recipe_wire_len * 2u + 1u,
                       "factory.recipe.hex");
        if (!manifest_hex || !recipe_hex_s)
            LOG_ERR(PF_LOG, "hex alloc");
        hex_take(manifest_hex, prepared.manifest_wire_len * 2u + 1u,
                 prepared.manifest_wire, prepared.manifest_wire_len);
        hex_take(recipe_hex_s, prepared.recipe_wire_len * 2u + 1u,
                 prepared.recipe_wire, prepared.recipe_wire_len);
        bool ok_a = factory_store_journey(args, args->store_a, release_hex,
                                          manifest_hex, recipe_hex_s,
                                          prepared.recipe_wire,
                                          prepared.recipe_wire_len,
                                          root_hex_, &rep, "a", &sa,
                                          &fast_stats);
        bool ok_b = ok_a &&
            factory_store_journey(args, args->store_b, release_hex,
                                  manifest_hex, recipe_hex_s,
                                  prepared.recipe_wire,
                                  prepared.recipe_wire_len, root_hex_, &rep,
                                  "b", &sb, &fast_stats);
        (void)ok_b;
        free(manifest_hex);
        free(recipe_hex_s);
    }

    /* 7. exact dependency plan (zcl.dep_plan.v1; local evidence only) */
    char dep_plan_sha3[65] = {0};
    if (!rep.failed && prepared_ok && args->dep_plan_path) {
        s = pf_step_begin(&rep, "dep_plan");
        t0 = now_ms();
        if (factory_dep_plan(args, root_hex_, prepared.recipe_wire,
                             prepared.recipe_wire_len, dep_plan_sha3,
                             &fast_stats, error, sizeof(error)))
            pf_step_ok(s, t0);
        else
            (void)pf_step_fail(&rep, s, t0, error);
    }

    /* 8. self-screened admission (census construction) */
    s = pf_step_begin(&rep, "admission");
    t0 = now_ms();
    if (!rep.failed) {
        char default_seed[PF_PATH_CAP];
        const char *seed_path = args->signer_seed_file;
        if (!seed_path) {
            const char *home = getenv("HOME");
            if (!home ||
                snprintf(default_seed, sizeof(default_seed),
                         "%s/.config/zclassic23/corpus-census-signer.seed",
                         home) >= (int)sizeof(default_seed)) {
                (void)pf_step_fail(&rep, s, t0,
                                   "HOME unset; pass --signer-seed-file");
                goto admission_done;
            }
            seed_path = default_seed;
        }
        uint8_t seed[32];
        if (!pf_seed_load_or_create(seed_path, seed)) {
            (void)pf_step_fail(&rep, s, t0, "signer seed load/create");
            goto admission_done;
        }
        bool ok = factory_admission(args, &info, &prepared, release_id,
                                    seed, admission_root, &admission_wire,
                                    &admission_wire_len, error,
                                    sizeof(error));
        memory_cleanse(seed, sizeof(seed));
        if (!ok)
            (void)pf_step_fail(&rep, s, t0,
                               error[0] ? error : "admission failed");
        else
            pf_step_ok(s, t0);
    }
admission_done:

    /* 9. corpus registration */
    if (!rep.failed && args->register_corpus) {
        s = pf_step_begin(&rep, "register_corpus");
        t0 = now_ms();
        error[0] = '\0';
        if (factory_register_corpus(args->census_def, info.name, root_hex_,
                                    args->store_a, args->kind, info.license,
                                    error, sizeof(error))) {
            corpus_registered = true;
            (void)snprintf(corpus_note, sizeof(corpus_note),
                "rerun: make corpus-census CORPUS_OUT=corpus "
                "CORPUS_SEQUENCE=<n> CORPUS_PREDECESSOR_ROOT=<root> "
                "CORPUS_CUTOFF_HEIGHT=<h> CORPUS_CUTOFF_MTP=<m> "
                "CORPUS_QUALITY_ATTESTED=<0|1>");
            pf_step_ok(s, t0);
        } else {
            (void)pf_step_fail(&rep, s, t0, error);
        }
    }

    /* 10. report */
    uint64_t total_ms = now_ms() - t_start;
    struct json_value report;
    json_init(&report);
    json_set_object(&report);
    (void)json_push_kv_str(&report, "schema",
                           "zcl.package_factory.report.v1");
    (void)json_push_kv_bool(&report, "ok", !rep.failed);
    (void)json_push_kv_int(&report, "total_ms", (int64_t)total_ms);
    {
        struct json_value pkg;
        json_init(&pkg);
        json_set_object(&pkg);
        (void)json_push_kv_str(&pkg, "dir", args->package_dir);
        (void)json_push_kv_str(&pkg, "name", info.name);
        (void)json_push_kv_str(&pkg, "semver", info.semver);
        (void)json_push_kv_str(&pkg, "license", info.license);
        (void)json_push_kv_str(&pkg, "package_root", root_hex_);
        (void)json_push_kv_str(&pkg, "recipe_root", recipe_root_hex);
        (void)json_push_kv_str(&pkg, "release_id", release_id_hex);
        (void)json_push_kv_str(&pkg, "publisher_pubkey",
                               args->publisher_pubkey);
        (void)json_push_kv_int(&pkg, "publisher_sequence",
                               (int64_t)args->publisher_sequence);
        (void)json_push_kv_str(&pkg, "kind", args->kind);
        (void)json_push_kv(&report, "package", &pkg);
        json_free(&pkg);
    }
    {
        struct json_value stores;
        json_init(&stores);
        json_set_object(&stores);
        const struct {
            const char *key;
            const char *dir;
            const struct store_result *sr;
        } rows[2] = {
            {"a", args->store_a, &sa},
            {"b", args->store_b, &sb},
        };
        for (size_t i = 0; i < 2; i++) {
            struct json_value so;
            json_init(&so);
            json_set_object(&so);
            /* The store LABEL, not the datadir. This report is a tracked
             * file under corpus/factory/; an absolute datadir here published
             * the operator's home directory in every one of them. The label
             * is the store's identity — where it lives is operator-local and
             * is supplied at run time by --store-a/--store-b. */
            {
                char label[PF_PATH_CAP];
                char lerr[PF_ERROR_CAP] = {0};
                (void)json_push_kv_str(&so, "store",
                    pf_store_label(rows[i].dir, label, sizeof(label), lerr,
                                   sizeof(lerr)) ? label : "unnamed");
            }
            (void)json_push_kv_bool(&so, "published", rows[i].sr->publish_ok);
            (void)json_push_kv_bool(&so, "installed", rows[i].sr->add_ok);
            (void)json_push_kv_str(&so, "plan_id", rows[i].sr->plan_id);
            (void)json_push_kv_str(&so, "receipt_quick",
                                   rows[i].sr->receipt_quick);
            (void)json_push_kv_str(&so, "receipt_standard",
                                   rows[i].sr->receipt_standard);
            (void)json_push_kv_bool(&so, "reproduced",
                                    rows[i].sr->reproduced);
            (void)json_push_kv_str(&so, "storage_ack",
                rows[i].sr->storage_ack_status[0]
                    ? rows[i].sr->storage_ack_status
                    : "not_attempted");
            (void)json_push_kv(&stores, rows[i].key, &so);
            json_free(&so);
        }
        (void)json_push_kv(&report, "stores", &stores);
        json_free(&stores);
    }
    {
        char ahex[65];
        pf_root_hex(admission_root, ahex);
        struct json_value adm;
        json_init(&adm);
        json_set_object(&adm);
        (void)json_push_kv_str(&adm, "admission_root",
                               root_nonzero(admission_root) ? ahex : "");
        if (admission_wire) {
            size_t hex_len = admission_wire_len * 2u;
            char *hex = zcl_malloc(hex_len + 1u, "factory.adm.hex");
            if (!hex)
                LOG_ERR(PF_LOG, "admission hex alloc");
            zcl_hex_encode(admission_wire, admission_wire_len, hex);
            (void)json_push_kv_str(&adm, "admission_wire", hex);
            free(hex);
        }
        (void)json_push_kv_str(&adm, "screen", "self-screened");
        (void)json_push_kv(&report, "admission", &adm);
        json_free(&adm);
    }
    if (args->dep_plan_path) {
        struct json_value dp;
        json_init(&dp);
        json_set_object(&dp);
        (void)json_push_kv_str(&dp, "schema", "zcl.dep_plan.v1");
        (void)json_push_kv_str(&dp, "path", args->dep_plan_path);
        (void)json_push_kv_str(&dp, "sha3", dep_plan_sha3);
        (void)json_push_kv(&report, "dep_plan", &dp);
        json_free(&dp);
    }
    if (args->fast_cache_dir) {
        struct json_value fc;
        json_init(&fc);
        json_set_object(&fc);
        (void)json_push_kv_str(&fc, "schema", "zcl.fastobj.v1");
        /* Name only — this report is committed and the cache is a local
         * build-scratch directory whose absolute path identifies the
         * operator's account, never the evidence. */
        {
            char label[PF_PATH_CAP];
            char lerr[PF_ERROR_CAP] = {0};
            (void)json_push_kv_str(&fc, "dir",
                pf_store_label(args->fast_cache_dir, label, sizeof(label),
                               lerr, sizeof(lerr)) ? label : "unnamed");
        }
        (void)json_push_kv_int(&fc, "hits", (int64_t)fast_stats.hits);
        (void)json_push_kv_int(&fc, "misses", (int64_t)fast_stats.misses);
        (void)json_push_kv_int(&fc, "objects_reused_bytes",
                               (int64_t)fast_stats.reused_bytes);
        (void)json_push_kv_str(&fc, "admission", "local_candidate");
        (void)json_push_kv_str(&fc, "note",
            "quarantined local candidate cache; cached objects speed up "
            "only this node's confined rebuilds and are never attestation "
            "or admission evidence");
        (void)json_push_kv_str(&fc, "applies_to",
            "package-verify --zbuild-package-* rebuilds (second receipt "
            "and dep plan steps)");
        (void)json_push_kv(&report, "fast_cache", &fc);
        json_free(&fc);
    }
    {
        struct json_value steps;
        json_init(&steps);
        json_set_array(&steps);
        for (size_t i = 0; i < rep.step_count; i++) {
            struct json_value so;
            json_init(&so);
            json_set_object(&so);
            (void)json_push_kv_str(&so, "name", rep.steps[i].name);
            (void)json_push_kv_bool(&so, "ok", rep.steps[i].ok);
            (void)json_push_kv_int(&so, "ms", (int64_t)rep.steps[i].ms);
            if (rep.steps[i].error[0])
                (void)json_push_kv_str(&so, "error", rep.steps[i].error);
            (void)json_push_back(&steps, &so);
            json_free(&so);
        }
        (void)json_push_kv(&report, "steps", &steps);
        json_free(&steps);
    }
    {
        struct json_value disc;
        json_init(&disc);
        json_set_array(&disc);
        struct json_value v;
#define PF_DISCLOSE(text)                        \
        json_init(&v);                           \
        json_set_str(&v, text);                  \
        (void)json_push_back(&disc, &v);         \
        json_free(&v)
        PF_DISCLOSE("same-host reproduction: both confined builds ran on "
                    "one host with one toolchain (quick + standard flag "
                    "profiles); independent-operator reproduction is "
                    "future work");
        PF_DISCLOSE("self-screen admission: the commons_admission.v1 is "
                    "self-signed SELF_SCREENED (tier 0); zero independent "
                    "operator groups participated");
        PF_DISCLOSE("offline run: no network durability — storage_ack "
                    "needs the live DHT service; durable_hosting is "
                    "unavailable_offline unless a store reports otherwise");
        PF_DISCLOSE("the approved_verifiers allowlist in each store was "
                    "created by the factory with the publisher key so the "
                    "verify command could run; no verifier quorum was "
                    "reached and none is claimed");
#undef PF_DISCLOSE
        (void)json_push_kv(&report, "disclosures", &disc);
        json_free(&disc);
    }
    (void)json_push_kv_str(&report, "durable_hosting",
        (sa.storage_ack_status[0] &&
         strcmp(sa.storage_ack_status, "unavailable_offline") != 0) ||
        (sb.storage_ack_status[0] &&
         strcmp(sb.storage_ack_status, "unavailable_offline") != 0)
            ? "attempted"
            : "unavailable_offline");
    (void)json_push_kv_bool(&report, "corpus_registered",
                            corpus_registered);
    if (corpus_note[0])
        (void)json_push_kv_str(&report, "corpus_next_step", corpus_note);
    {
        size_t need = json_write(&report, NULL, 0);
        char *text = zcl_malloc(need + 2u, "factory.report.out");
        if (!text)
            LOG_ERR(PF_LOG, "report buffer alloc");
        size_t written = json_write(&report, text, need + 1u);
        if (written > need)
            LOG_ERR(PF_LOG, "report write overflow");
        text[written] = '\n';
        if (!pf_write_atomic(args->report_path, (const uint8_t *)text,
                             written + 1u)) {
            free(text);
            json_free(&report);
            LOG_ERR(PF_LOG, "cannot write report %s", args->report_path);
        }
        free(text);
    }
    json_free(&report);

    printf("package-factory: %s package=%s root=%s release=%s\n",
           rep.failed ? "FAILED" : "ok", info.name, root_hex_,
           release_id_hex);
    printf("  reproduced: storeA=%d storeB=%d  durable_hosting=%s\n",
           (int)sa.reproduced, (int)sb.reproduced,
           (sa.storage_ack_status[0] &&
            strcmp(sa.storage_ack_status, "unavailable_offline") != 0)
               ? sa.storage_ack_status
               : "unavailable_offline");
    if (corpus_registered)
        printf("  corpus: registered in %s — %s\n", args->census_def,
               corpus_note);
    printf("  report: %s\n", args->report_path);

    for (size_t i = 0; i < rep.step_count; i++)
        free((void *)rep.steps[i].name);
    free(release_wire);
    free(admission_wire);
    if (prepared_ok) vcs_package_prepared_free(&prepared);
    gate_info_free(&info);
    return rep.failed ? 1 : 0;
}

/* ── selftest ─────────────────────────────────────────────────────── */

/* Keys whose values legitimately differ between two otherwise identical
 * factory runs: timings (total_ms, ms), the run-local fast-cache counters
 * (fast_cache), the add-plan id (a fresh plan nonce each run), and step
 * error TEXT (the storage_ack refusal embeds volatile response fields —
 * the ok flags still assert the outcome). */
static bool pf_json_volatile_key(const char *key)
{
    return strcmp(key, "total_ms") == 0 || strcmp(key, "ms") == 0 ||
           strcmp(key, "fast_cache") == 0 || strcmp(key, "plan_id") == 0 ||
           strcmp(key, "error") == 0;
}

/* Recursive structural equality with the volatile keys skipped. */
static bool pf_json_equiv(const struct json_value *a,
                          const struct json_value *b)
{
    if (a->type != b->type)
        return false;
    switch (a->type) {
    case JSON_NULL:
        return true;
    case JSON_BOOL:
        return a->val.b == b->val.b;
    case JSON_INT:
        return a->val.i == b->val.i;
    case JSON_REAL:
        return a->val.d == b->val.d;
    case JSON_STR:
        return strcmp(a->val.s, b->val.s) == 0;
    case JSON_ARR:
        if (a->num_children != b->num_children)
            return false;
        for (size_t i = 0; i < a->num_children; i++)
            if (!pf_json_equiv(&a->children[i], &b->children[i]))
                return false;
        return true;
    case JSON_OBJ: {
        size_t na = 0, nb = 0;
        for (size_t i = 0; i < a->num_children; i++)
            if (!pf_json_volatile_key(a->keys[i]))
                na++;
        for (size_t i = 0; i < b->num_children; i++)
            if (!pf_json_volatile_key(b->keys[i]))
                nb++;
        if (na != nb)
            return false;
        for (size_t i = 0; i < a->num_children; i++) {
            if (pf_json_volatile_key(a->keys[i]))
                continue;
            const struct json_value *bv = json_get(b, a->keys[i]);
            if (!bv || !pf_json_equiv(&a->children[i], bv))
                return false;
        }
        return true;
    }
    }
    return false;
}

static int cmd_selftest(const char *repo, const char *scratch,
                        const char *bin_dir)
{
    char error[PF_ERROR_CAP];
    /* The scratch root must stay under test-tmp/ (gitignored scratch;
     * never a real datadir). */
    if (strncmp(scratch, "test-tmp/", 9) != 0 &&
        strstr(scratch, "/test-tmp/") == NULL)
        LOG_ERR(PF_LOG, "selftest scratch %s must live under test-tmp/",
                scratch);
    char fixture[PF_PATH_CAP];
    if (snprintf(fixture, sizeof(fixture),
                 "%s/lib/test/fixtures/zcode/tiny-lines", repo) >=
        (int)sizeof(fixture))
        LOG_ERR(PF_LOG, "fixture path overflow");
    if (access(fixture, R_OK) != 0)
        LOG_ERR(PF_LOG, "fixture %s not readable", fixture);

    /* Fresh scratch. */
    {
        char *rm_argv[] = {(char *)"rm", (char *)"-rf", (char *)scratch,
                           NULL};
        char devnull[16];
        if (pf_spawn(rm_argv, NULL, 0, devnull, sizeof(devnull)) != 0)
            LOG_ERR(PF_LOG, "cannot clear scratch %s", scratch);
    }
    if (!pf_mkdir_p(scratch))
        return 1;
    char pkg[PF_PATH_CAP], key[PF_PATH_CAP], store_a[PF_PATH_CAP],
         store_b[PF_PATH_CAP], report[PF_PATH_CAP], dplan[PF_PATH_CAP],
         fastcache[PF_PATH_CAP], report2[PF_PATH_CAP];
    if (snprintf(pkg, sizeof(pkg), "%s/pkg", scratch) >= (int)sizeof(pkg) ||
        snprintf(key, sizeof(key), "%s/key", scratch) >= (int)sizeof(key) ||
        snprintf(store_a, sizeof(store_a), "%s/storeA", scratch) >=
            (int)sizeof(store_a) ||
        snprintf(store_b, sizeof(store_b), "%s/storeB", scratch) >=
            (int)sizeof(store_b) ||
        snprintf(report, sizeof(report), "%s/report.json", scratch) >=
            (int)sizeof(report) ||
        snprintf(dplan, sizeof(dplan), "%s/plan.json", scratch) >=
            (int)sizeof(dplan) ||
        snprintf(fastcache, sizeof(fastcache), "%s/fastcache", scratch) >=
            (int)sizeof(fastcache) ||
        snprintf(report2, sizeof(report2), "%s/report2.json", scratch) >=
            (int)sizeof(report2))
        LOG_ERR(PF_LOG, "selftest path overflow");
    {
        char *cp_argv[] = {(char *)"cp", (char *)"-r", fixture,
                           pkg, NULL};
        char out[256];
        if (pf_spawn(cp_argv, NULL, 0, out, sizeof(out)) != 0)
            LOG_ERR(PF_LOG, "fixture copy failed: %s", out);
    }
    /* Throwaway key: the signer's keygen mode. */
    char pubkey[256];
    {
        char bin[PF_PATH_CAP];
        if (snprintf(bin, sizeof(bin), "%s/zclassic23-package-sign",
                     bin_dir) >= (int)sizeof(bin))
            LOG_ERR(PF_LOG, "signer path overflow");
        char *argv[] = {bin, (char *)"--generate", key, NULL};
        if (pf_spawn(argv, NULL, 0, pubkey, sizeof(pubkey)) != 0)
            LOG_ERR(PF_LOG, "keygen failed");
        size_t len = strlen(pubkey);
        while (len && isspace((unsigned char)pubkey[len - 1]))
            pubkey[--len] = '\0';
        if (strlen(pubkey) != 66)
            LOG_ERR(PF_LOG, "keygen returned no pubkey");
        struct run_args args;
        memset(&args, 0, sizeof(args));
        args.package_dir = pkg;
        args.key_file = key;
        args.publisher_pubkey = pubkey;
        args.store_a = store_a;
        args.store_b = store_b;
        args.report_path = report;
        args.dep_plan_path = dplan;
        args.fast_cache_dir = fastcache;
        args.bin_dir = bin_dir;
        args.chain_id = "zclassic-main";
        args.kind = "ai";
        args.publisher_sequence = 1;
        args.cutoff_height = 1;
        args.cutoff_mtp = 1700000000;
        int rc = cmd_run(&args);
        if (rc != 0)
            LOG_ERR(PF_LOG, "selftest: factory run failed (rc=%d)", rc);
    }

    /* Assert the report: every step ok, reproduced both sides. */
    {
        uint8_t *text = NULL;
        size_t len = 0;
        if (!pf_read_file(report, PF_CLI_STDOUT_CAP, &text, &len))
            LOG_ERR(PF_LOG, "selftest: report %s missing", report);
        struct json_value doc;
        json_init(&doc);
        if (!json_read(&doc, (const char *)text, len)) {
            free(text);
            LOG_ERR(PF_LOG, "selftest: report unparsable");
        }
        free(text);
        const struct json_value *ok = json_get(&doc, "ok");
        const struct json_value *ra = json_get(
            json_get(json_get(&doc, "stores"), "a"), "reproduced");
        const struct json_value *rb = json_get(
            json_get(json_get(&doc, "stores"), "b"), "reproduced");
        bool pass = ok && json_get_bool(ok) && ra && json_get_bool(ra) &&
                    rb && json_get_bool(rb);
        json_free(&doc);
        if (!pass)
            LOG_ERR(PF_LOG, "selftest: report assertions failed");
        printf("selftest: gate/publish/reproduce/report ok (report=%s)\n",
               report);
    }

    /* The exact dependency plan exists, parses as zcl.dep_plan.v1, and the
     * report's plan hash matches the plan file bytes. */
    {
        uint8_t *text = NULL;
        size_t len = 0;
        if (!pf_read_file(report, PF_CLI_STDOUT_CAP, &text, &len))
            LOG_ERR(PF_LOG, "selftest: report re-read for plan failed");
        struct json_value doc;
        json_init(&doc);
        if (!json_read(&doc, (const char *)text, len)) {
            free(text);
            LOG_ERR(PF_LOG, "selftest: report unparsable (plan)");
        }
        free(text);
        const struct json_value *dp = json_get(&doc, "dep_plan");
        const char *path = json_get_str(json_get(dp, "path"));
        const char *sha = json_get_str(json_get(dp, "sha3"));
        /* Copy before json_free: the strings point into the parsed doc. */
        char path_buf[PF_PATH_CAP], sha_buf[65];
        (void)snprintf(path_buf, sizeof(path_buf), "%s", path);
        (void)snprintf(sha_buf, sizeof(sha_buf), "%s", sha);
        bool pass = path_buf[0] && strlen(sha_buf) == 64;
        uint8_t *plan = NULL;
        size_t plan_len = 0;
        if (pass)
            pass = pf_read_file(path_buf, PF_CLI_STDOUT_CAP, &plan,
                                &plan_len);
        if (pass) {
            uint8_t digest[32];
            sha3_256(plan, plan_len, digest);
            char hex[65];
            zcl_hex_encode(digest, 32, hex);
            pass = strcmp(hex, sha_buf) == 0;
        }
        if (pass) {
            struct json_value pdoc;
            json_init(&pdoc);
            pass = json_read(&pdoc, (const char *)plan, plan_len);
            if (pass) {
                const char *schema = json_get_str(json_get(&pdoc, "schema"));
                const struct json_value *tus =
                    json_get(&pdoc, "translation_units");
                pass = strcmp(schema, "zcl.dep_plan.v1") == 0 && tus &&
                       tus->type == JSON_ARR && tus->num_children > 0;
            }
            json_free(&pdoc);
            free(plan);
        }
        json_free(&doc);
        if (!pass)
            LOG_ERR(PF_LOG, "selftest: dependency plan missing, not "
                    "zcl.dep_plan.v1, or report hash mismatch");
        printf("selftest: dep_plan ok (path=%s sha3=%.16s...)\n", path_buf,
               sha_buf);
    }

    /* Second full run against the SAME fast cache with only the stores
     * wiped: every confined rebuild must now be a cache hit, and the
     * report must equal run 1's modulo the volatile keys. */
    {
        char *rm_argv[] = {(char *)"rm", (char *)"-rf", store_a, store_b,
                           NULL};
        char devnull[16];
        if (pf_spawn(rm_argv, NULL, 0, devnull, sizeof(devnull)) != 0)
            LOG_ERR(PF_LOG, "selftest: store wipe failed");
        struct run_args args2;
        memset(&args2, 0, sizeof(args2));
        args2.package_dir = pkg;
        args2.key_file = key;
        args2.publisher_pubkey = pubkey;
        args2.store_a = store_a;
        args2.store_b = store_b;
        args2.report_path = report2;
        args2.dep_plan_path = dplan;
        args2.fast_cache_dir = fastcache;
        args2.bin_dir = bin_dir;
        args2.chain_id = "zclassic-main";
        args2.kind = "ai";
        args2.publisher_sequence = 1;
        args2.cutoff_height = 1;
        args2.cutoff_mtp = 1700000000;
        int rc = cmd_run(&args2);
        if (rc != 0)
            LOG_ERR(PF_LOG, "selftest: factory re-run failed (rc=%d)", rc);
        uint8_t *t1 = NULL, *t2 = NULL;
        size_t l1 = 0, l2 = 0;
        if (!pf_read_file(report, PF_CLI_STDOUT_CAP, &t1, &l1) ||
            !pf_read_file(report2, PF_CLI_STDOUT_CAP, &t2, &l2))
            LOG_ERR(PF_LOG, "selftest: cannot re-read both reports");
        struct json_value d1, d2;
        json_init(&d1);
        json_init(&d2);
        bool pass = json_read(&d1, (const char *)t1, l1) &&
                    json_read(&d2, (const char *)t2, l2);
        free(t1);
        free(t2);
        if (!pass)
            LOG_ERR(PF_LOG, "selftest: report pair unparsable");
        const struct json_value *fc2 = json_get(&d2, "fast_cache");
        const struct json_value *fc2_hits = json_get(fc2, "hits");
        const struct json_value *fc2_misses = json_get(fc2, "misses");
        const struct json_value *fc1 = json_get(&d1, "fast_cache");
        const struct json_value *fc1_misses = json_get(fc1, "misses");
        pass = fc2_hits && fc2_misses && fc1_misses &&
               json_get_int(fc2_hits) >= 3 && json_get_int(fc2_misses) == 0 &&
               json_get_int(fc1_misses) >= 2;
        if (!pass)
            LOG_ERR(PF_LOG, "selftest: fast cache did not turn the re-run "
                    "into all hits");
        pass = pf_json_equiv(&d1, &d2);
        json_free(&d1);
        json_free(&d2);
        if (!pass)
            LOG_ERR(PF_LOG, "selftest: cached re-run report diverges from "
                    "the clean run (beyond volatile keys)");
        printf("selftest: fast cache ok (re-run all hits, reports equal "
               "modulo volatile keys)\n");
    }

    /* Census intake: a scratch def with ONLY the package line, pointing at
     * scratch store A; run the census and require the package COUNTED with
     * test LOC and the reproduced bit. */
    uint8_t *rtext = NULL;
    size_t rlen = 0;
    if (!pf_read_file(report, PF_CLI_STDOUT_CAP, &rtext, &rlen))
        LOG_ERR(PF_LOG, "selftest: report re-read failed");
    char root_hex_[65] = {0};
    {
        struct json_value doc;
        json_init(&doc);
        bool parsed = json_read(&doc, (const char *)rtext, rlen);
        free(rtext);
        if (!parsed)
            LOG_ERR(PF_LOG, "selftest: report unparsable (2)");
        const char *r = json_get_str(
            json_get(json_get(&doc, "package"), "package_root"));
        if (!r || strlen(r) != 64) {
            json_free(&doc);
            LOG_ERR(PF_LOG, "selftest: report has no package_root");
        }
        (void)snprintf(root_hex_, sizeof(root_hex_), "%s", r);
        json_free(&doc);
    }
    char store_a_abs[PF_PATH_CAP];
    if (!realpath(store_a, store_a_abs))
        LOG_ERR(PF_LOG, "selftest: realpath %s: %s", store_a,
                strerror(errno));
    char def_path[PF_PATH_CAP], census_out[PF_PATH_CAP];
    if (snprintf(def_path, sizeof(def_path), "%s/scopes.def", scratch) >=
            (int)sizeof(def_path) ||
        snprintf(census_out, sizeof(census_out), "%s/census", scratch) >=
            (int)sizeof(census_out))
        LOG_ERR(PF_LOG, "selftest path overflow");
    /* The def carries the store LABEL; the directory it hangs off is passed
     * to the census as --store-root. This is the end-to-end proof that the
     * label form resolves — and that no absolute path is ever written into a
     * scopes.def, not even a scratch one. */
    char store_a_label[PF_PATH_CAP];
    char store_a_root[PF_PATH_CAP];
    {
        char lerr[PF_ERROR_CAP] = {0};
        if (!pf_store_label(store_a_abs, store_a_label,
                            sizeof(store_a_label), lerr, sizeof(lerr)))
            LOG_ERR(PF_LOG, "selftest: store label: %s", lerr);
        size_t root_len = strlen(store_a_abs) - strlen(store_a_label);
        if (root_len < 2u || root_len >= sizeof(store_a_root))
            LOG_ERR(PF_LOG, "selftest: store '%s' has no parent directory",
                    store_a_abs);
        memcpy(store_a_root, store_a_abs, root_len - 1u); /* drop the '/' */
        store_a_root[root_len - 1u] = '\0';
    }
    {
        size_t line_cap = strlen(store_a_label) + 160u;
        char *line = zcl_malloc(line_cap, "factory.selftest.def");
        if (!line)
            LOG_ERR(PF_LOG, "def line alloc");
        int n = snprintf(line, line_cap,
                         "package fixture/tiny-lines | root %s | store %s | "
                         "kind ai | spdx MIT\n", root_hex_, store_a_label);
        if (n <= 0 || (size_t)n >= line_cap ||
            !pf_write_atomic(def_path, (const uint8_t *)line, (size_t)n)) {
            free(line);
            LOG_ERR(PF_LOG, "selftest: cannot write scratch def");
        }
        free(line);
    }
    {
        char bin[PF_PATH_CAP];
        if (snprintf(bin, sizeof(bin), "%s/corpus-census", bin_dir) >=
            (int)sizeof(bin))
            LOG_ERR(PF_LOG, "census path overflow");
        char *argv[] = {bin,
                        (char *)"--repo", (char *)repo,
                        (char *)"--def", def_path,
                        (char *)"--out", census_out,
                        (char *)"--store-root", store_a_root,
                        (char *)"--cutoff-height", (char *)"1",
                        (char *)"--cutoff-mtp", (char *)"1700000000",
                        NULL};
        char *out = zcl_malloc(PF_CLI_STDOUT_CAP, "factory.census.out");
        if (!out)
            LOG_ERR(PF_LOG, "census stdout alloc");
        int rc = pf_spawn(argv, NULL, 0, out, PF_CLI_STDOUT_CAP);
        if (rc != 0) {
            fprintf(stderr, "%s", out);
            free(out);
            LOG_ERR(PF_LOG, "selftest: corpus-census exit %d", rc);
        }
        printf("selftest: census: %s", strchr(out, 'c') ? out : "");
        free(out);
    }
    /* Assert the census counted the package. */
    char report_path[PF_PATH_CAP];
    if (snprintf(report_path, sizeof(report_path),
                 "%s/report-000001.json", census_out) >=
        (int)sizeof(report_path))
        LOG_ERR(PF_LOG, "selftest path overflow");
    {
        uint8_t *text = NULL;
        size_t len = 0;
        if (!pf_read_file(report_path, PF_CLI_STDOUT_CAP, &text, &len))
            LOG_ERR(PF_LOG, "selftest: census report missing");
        struct json_value doc;
        json_init(&doc);
        if (!json_read(&doc, (const char *)text, len)) {
            free(text);
            LOG_ERR(PF_LOG, "selftest: census report unparsable");
        }
        free(text);
        const struct json_value *scopes = json_get(&doc, "scopes");
        bool pass = false;
        if (scopes && scopes->type == JSON_ARR &&
            scopes->num_children == 1) {
            const struct json_value *scope = json_at(scopes, 0);
            const struct json_value *counted = json_get(scope, "counted");
            const struct json_value *tloc =
                json_get(scope, "test_loc_would_be");
            const struct json_value *repro = json_get(scope, "reproduced");
            pass = counted && json_get_bool(counted) && tloc &&
                   json_get_int(tloc) > 0 && repro &&
                   json_get_bool(repro);
        }
        json_free(&doc);
        if (!pass)
            LOG_ERR(PF_LOG, "selftest: package NOT counted with test LOC "
                    "and reproduction in the census");
    }
    printf("selftest: census intake ok (package counted, test_loc>0, "
           "reproduced)\n");
    printf("selftest: PASS (scratch left at %s)\n", scratch);
    (void)error;
    return 0;
}

/* ── argument parsing / main ──────────────────────────────────────── */

static void usage(FILE *stream)
{
    fprintf(stream,
        "usage:\n"
        "  package-factory run --package <dir> --publisher-key-file <key>\n"
        "      --publisher-pubkey <66hex> --store-a <datadirA>\n"
        "      --store-b <datadirB> --report <out.json>\n"
        "      [--publisher-sequence N] [--kind human|ai|import]\n"
        "      [--chain-id <id>] [--cutoff-height N] [--cutoff-mtp N]\n"
        "      [--signer-seed-file PATH] [--bin-dir <dir>]\n"
        "      [--dep-plan <out.json>]  (default: <report> with\n"
        "      .report.json replaced by .plan.json)\n"
        "      [--fast-cache <dir>]  (default: $XDG_CACHE_HOME or\n"
        "      $HOME/.cache, plus /zclassic23/fast-obj; per-TU object\n"
        "      cache for the confined rebuilds, admission=local_candidate;\n"
        "      pass an empty --fast-cache= to disable)\n"
        "      [--register-corpus --census-def corpus/scopes.def]\n"
        "  package-factory pin-dep --package <dir> --dep-name <name>\n"
        "      --dep-root <64hex>\n"
        "  package-factory selftest [--repo <repo>] [--scratch <dir>]\n"
        "      [--bin-dir <dir>]\n");
}

static bool parse_u64(const char *s, uint64_t *out)
{
    if (!s || !*s) return false;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || !end || *end) return false;
    *out = (uint64_t)v;
    return true;
}

static bool parse_i64(const char *s, int64_t *out)
{
    if (!s || !*s) return false;
    errno = 0;
    char *end = NULL;
    long long v = strtoll(s, &end, 10);
    if (errno || !end || *end) return false;
    *out = (int64_t)v;
    return true;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(stderr);
        return 2;
    }
    const char *mode = argv[1];
    /* Generic --key value / --key=value parsing. */
    const char *package_dir = NULL, *key_file = NULL, *pubkey = NULL,
               *store_a = NULL, *store_b = NULL, *report = NULL,
               *bin_dir = "build/bin", *census_def = "corpus/scopes.def",
               *seed_file = NULL, *chain_id = "zclassic-main",
               *kind = "ai", *dep_name = NULL, *dep_root = NULL,
               *repo = ".", *scratch = "test-tmp/factory-selftest",
               *dep_plan = NULL, *fast_cache = NULL;
    char dep_plan_default[PF_PATH_CAP];
    char fast_cache_default[PF_PATH_CAP];
    uint64_t sequence = 1, cutoff_height = 1;
    int64_t cutoff_mtp = 1700000000;
    bool register_corpus = false;
    for (int i = 2; i < argc; i++) {
        char *arg = argv[i];
        if (strncmp(arg, "--", 2) != 0) {
            usage(stderr);
            return 2;
        }
        char *eq = strchr(arg, '=');
        const char *value = NULL;
        char keyb[64];
        if (eq) {
            size_t klen = (size_t)(eq - arg);
            if (klen >= sizeof(keyb)) return 2;
            memcpy(keyb, arg, klen);
            keyb[klen] = '\0';
            value = eq + 1;
        } else {
            if (strlen(arg) >= sizeof(keyb)) return 2;
            strcpy(keyb, arg);
            if (strcmp(keyb, "--register-corpus") == 0) {
                register_corpus = true;
                continue;
            }
            if (i + 1 >= argc) {
                usage(stderr);
                return 2;
            }
            value = argv[++i];
        }
        if (strcmp(keyb, "--package") == 0) package_dir = value;
        else if (strcmp(keyb, "--publisher-key-file") == 0) key_file = value;
        else if (strcmp(keyb, "--publisher-pubkey") == 0) pubkey = value;
        else if (strcmp(keyb, "--store-a") == 0) store_a = value;
        else if (strcmp(keyb, "--store-b") == 0) store_b = value;
        else if (strcmp(keyb, "--report") == 0) report = value;
        else if (strcmp(keyb, "--dep-plan") == 0) dep_plan = value;
        else if (strcmp(keyb, "--fast-cache") == 0) fast_cache = value;
        else if (strcmp(keyb, "--bin-dir") == 0) bin_dir = value;
        else if (strcmp(keyb, "--census-def") == 0) census_def = value;
        else if (strcmp(keyb, "--signer-seed-file") == 0) seed_file = value;
        else if (strcmp(keyb, "--chain-id") == 0) chain_id = value;
        else if (strcmp(keyb, "--kind") == 0) kind = value;
        else if (strcmp(keyb, "--dep-name") == 0) dep_name = value;
        else if (strcmp(keyb, "--dep-root") == 0) dep_root = value;
        else if (strcmp(keyb, "--repo") == 0) repo = value;
        else if (strcmp(keyb, "--scratch") == 0) scratch = value;
        else if (strcmp(keyb, "--publisher-sequence") == 0) {
            if (!parse_u64(value, &sequence) || !sequence) return 2;
        } else if (strcmp(keyb, "--cutoff-height") == 0) {
            if (!parse_u64(value, &cutoff_height) || !cutoff_height)
                return 2;
        } else if (strcmp(keyb, "--cutoff-mtp") == 0) {
            if (!parse_i64(value, &cutoff_mtp) || cutoff_mtp <= 0) return 2;
        } else {
            usage(stderr);
            return 2;
        }
    }
    if (strcmp(kind, "human") != 0 && strcmp(kind, "ai") != 0 &&
        strcmp(kind, "import") != 0) {
        usage(stderr);
        return 2;
    }

    if (strcmp(mode, "run") == 0) {
        if (!package_dir || !key_file || !pubkey || !store_a || !store_b ||
            !report || (register_corpus && !census_def)) {
            usage(stderr);
            return 2;
        }
        if (!dep_plan) {
            /* Default: the report's sibling, <name>.report.json →
             * <name>.plan.json. */
            static const char suffix[] = ".report.json";
            size_t rl = strlen(report);
            size_t sl = sizeof(suffix) - 1u;
            if (rl > sl && strcmp(report + rl - sl, suffix) == 0) {
                if (rl - sl + sizeof(".plan.json") >
                    sizeof(dep_plan_default))
                    return 2;
                memcpy(dep_plan_default, report, rl - sl);
                memcpy(dep_plan_default + rl - sl, ".plan.json",
                       sizeof(".plan.json"));
            } else if (snprintf(dep_plan_default, sizeof(dep_plan_default),
                                "%s.plan.json", report) >=
                           (int)sizeof(dep_plan_default)) {
                return 2;
            }
            dep_plan = dep_plan_default;
        }
        if (!fast_cache) {
            /* Default per-TU object cache: $XDG_CACHE_HOME/zclassic23/
             * fast-obj, else $HOME/.cache/zclassic23/fast-obj. An explicit
             * empty --fast-cache= disables the cache (no default). */
            const char *base = getenv("XDG_CACHE_HOME");
            int n;
            if (base && base[0])
                n = snprintf(fast_cache_default, sizeof(fast_cache_default),
                             "%s/zclassic23/fast-obj", base);
            else {
                const char *home = getenv("HOME");
                n = home ? snprintf(fast_cache_default,
                                    sizeof(fast_cache_default),
                                    "%s/.cache/zclassic23/fast-obj", home)
                         : -1;
            }
            if (n > 0 && (size_t)n < sizeof(fast_cache_default))
                fast_cache = fast_cache_default;
        }
        if (fast_cache && !fast_cache[0])
            fast_cache = NULL;
        struct run_args args = {
            .package_dir = package_dir,
            .key_file = key_file,
            .publisher_pubkey = pubkey,
            .store_a = store_a,
            .store_b = store_b,
            .report_path = report,
            .dep_plan_path = dep_plan,
            .fast_cache_dir = fast_cache,
            .bin_dir = bin_dir,
            .census_def = census_def,
            .signer_seed_file = seed_file,
            .chain_id = chain_id,
            .kind = kind,
            .publisher_sequence = sequence,
            .cutoff_height = cutoff_height,
            .cutoff_mtp = cutoff_mtp,
            .register_corpus = register_corpus,
        };
        return cmd_run(&args);
    }
    if (strcmp(mode, "pin-dep") == 0) {
        if (!package_dir || !dep_name || !dep_root) {
            usage(stderr);
            return 2;
        }
        return cmd_pin_dep(package_dir, dep_name, dep_root);
    }
    if (strcmp(mode, "selftest") == 0)
        return cmd_selftest(repo, scratch, bin_dir);
    usage(stderr);
    return 2;
}
