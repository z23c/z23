/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package-factory: the ONE reusable package factory for the C23 Commons.
 * Drives one package directory through the full acceptance journey —
 * gate, prepare, offline digest sign, seal, publish, install + confined
 * build in two independent stores, bit-identical reproduction, self-screened
 * admission, and optional corpus registration — reusing only the existing
 * machinery: contexts/commons/modules/vcs package_prepare/release/build/reproduce, the
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
 *       [--register-corpus --census-def contexts/commons/corpus/scopes.def]
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
#include "base/bytes.h"
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

/* The frozen family-c23.v1 policy root (docs/work/ZC23_FAMILY_COMMONS.md);
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

static bool root_zero(const uint8_t root[32])
{
    return !zcl_bytes_any_set(root, 32);
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
 * (the contexts/commons/modules/vcs revert convention). */
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
/* One stdin-writable tick of the pf_spawn pump: write what fits, closing
 * the pipe once the whole input is flushed or on a hard write error. */
static void pf_spawn_write_in(int fd, const uint8_t *input, size_t input_len,
                              size_t *written, bool *stdin_open)
{
    ssize_t w = write(fd, input + *written, input_len - *written);
    if (w > 0) {
        *written += (size_t)w;
        if (*written == input_len) {
            close(fd);
            *stdin_open = false;
        }
    } else if (w < 0 && errno != EINTR) {
        close(fd);
        *stdin_open = false;
    }
}

/* One stdout-readable tick of the pf_spawn pump. Returns false to stop the
 * pump (EOF or read error), true to keep looping. */
static bool pf_spawn_read_out(int fd, char *out, size_t cap, size_t *total)
{
    if (*total + 1u >= cap) {
        char drain[4096];
        ssize_t r = read(fd, drain, sizeof(drain));
        return r > 0; /* over cap: drain and truncate */
    }
    ssize_t r = read(fd, out + *total, cap - 1u - *total);
    if (r <= 0)
        return false;
    *total += (size_t)r;
    return true;
}

/* Write stdin, then read stdout to EOF. Inputs are bounded well under the
 * pipe buffer only for small payloads; the large ones (publish wires) go
 * through a writer/reader loop that interleaves to avoid a pipe-buffer
 * deadlock. Closes both fds before returning. */
static size_t pf_spawn_pump(int stdin_wr, int stdout_rd,
                            const uint8_t *input, size_t input_len,
                            char *out, size_t cap)
{
    size_t total = 0;
    size_t written = 0;
    bool stdin_open = input != NULL;
    if (!stdin_open) close(stdin_wr);
    for (;;) {
        fd_set rfds, wfds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_SET(stdout_rd, &rfds);
        int maxfd = stdout_rd;
        if (stdin_open) {
            FD_SET(stdin_wr, &wfds);
            if (stdin_wr > maxfd) maxfd = stdin_wr;
        }
        int ready = select(maxfd + 1, &rfds, &wfds, NULL, NULL);
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (stdin_open && FD_ISSET(stdin_wr, &wfds))
            pf_spawn_write_in(stdin_wr, input, input_len, &written,
                              &stdin_open);
        if (FD_ISSET(stdout_rd, &rfds) &&
            !pf_spawn_read_out(stdout_rd, out, cap, &total))
            break;
    }
    if (stdin_open) close(stdin_wr);
    close(stdout_rd);
    return total;
}

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
    int status = 0;
    size_t total = pf_spawn_pump(stdin_pipe[1], stdout_pipe[0], input,
                                 input_len, out, cap);
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
/* Build the argv for pf_spawn: bin path, optional extra flag, the
 * whitespace-split command words (tokenized in place inside words_copy),
 * then the trailing --input=- flag and NULL terminator. */
static void pf_cli_build_argv(char *bin, const char *extra_flag,
                              char *words_copy, char *argv[16])
{
    size_t argc = 0;
    argv[argc++] = bin;
    if (extra_flag) argv[argc++] = (char *)extra_flag;
    for (char *tok = strtok(words_copy, " ");
         tok && argc + 2u < 16u;
         tok = strtok(NULL, " "))
        argv[argc++] = tok;
    argv[argc++] = (char *)"--input=-";
    argv[argc] = NULL;
}

/* rc != 0 path of pf_cli: prefer the structured error body over the raw
 * (truncated) stdout line. Fills `error` and logs it. */
static void pf_cli_report_exit_error(const char *out, int rc,
                                     const char *command_words, char *error,
                                     size_t error_cap)
{
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
}

/* Reply-parsed-ok path of pf_cli: check the zcl.result.v1 envelope's ok
 * field. Fills `error` and logs it when refused. */
static bool pf_cli_check_ok(struct json_value *doc_out,
                            const char *command_words, char *error,
                            size_t error_cap)
{
    const struct json_value *okv = json_get(doc_out, "ok");
    if (okv && json_get_bool(okv))
        return true;
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
    pf_cli_build_argv(bin, extra_flag, words_copy, argv);
    char *out = zcl_malloc(PF_CLI_STDOUT_CAP, "factory.cli.out");
    if (!out) {
        free(words_copy);
        LOG_FAIL(PF_LOG, "cli stdout alloc");
    }
    int rc = pf_spawn(argv, (const uint8_t *)input,
                      input ? strlen(input) : 0, out, PF_CLI_STDOUT_CAP);
    free(words_copy);
    if (rc != 0) {
        pf_cli_report_exit_error(out, rc, command_words, error, error_cap);
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
    return pf_cli_check_ok(doc_out, command_words, error, error_cap);
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

/* Build the paged-request JSON body. Returns false on overflow (also
 * formats a refusal into `error`). */
static bool pf_paged_build_input(char *input, size_t input_cap,
                                 const char *id_key, const char *id_val,
                                 const char *datadir, size_t cursor,
                                 const char *command_words, char *error,
                                 size_t error_cap)
{
    int n = snprintf(input, input_cap,
                     "{\"%s\":\"%s\",\"datadir\":\"%s\",\"max_items\":%u,"
                     "\"cursor\":%zu}",
                     id_key, id_val, datadir, (unsigned)PF_STEP_PAGE_ITEMS,
                     cursor);
    if (n > 0 && (size_t)n < input_cap)
        return true;
    (void)snprintf(error, error_cap, "%s: paged input overflow",
                   command_words);
    LOG_ERROR(PF_LOG, "%s", error);
    return false;
}

/* Validate page shape: data.steps + data._page presence and type, and that
 * the requested cursor matches rows collected so far. Returns a refusal
 * reason, or NULL if the shape is fine. */
static const char *pf_paged_shape_why(const struct json_value *pdata,
                                      const struct json_value *psteps,
                                      const struct json_value *ppage,
                                      size_t cursor, size_t collected)
{
    if (!pdata || !psteps || psteps->type != JSON_ARR || !ppage ||
        ppage->type != JSON_OBJ)
        return "paged reply lacks data.steps or data._page";
    if (cursor != collected)
        return "paged reply is discontiguous";
    return NULL;
}

/* _page.next_cursor when truncated, else -1 (unread). */
static int64_t pf_paged_next_cursor(const struct json_value *ppage,
                                    bool truncated)
{
    if (!truncated)
        return -1;
    const struct json_value *ncv = json_get(ppage, "next_cursor");
    return ncv ? json_get_int(ncv) : -1;
}

/* Truncated-page advance check: next_cursor must exist and move forward. */
static const char *pf_paged_advance_why(bool truncated, size_t page_rows,
                                        int64_t next, size_t cursor)
{
    if (!truncated)
        return NULL;
    if (page_rows == 0 || next < 0 || (size_t)next <= cursor)
        return "_page.next_cursor does not advance";
    return NULL;
}

/* Every first-page scalar (other than steps/_page) must repeat identically
 * on every later page. */
static const char *pf_paged_scalars_why(const struct json_value *doc_out,
                                        const struct json_value *pdata)
{
    const struct json_value *mdata = json_get(doc_out, "data");
    for (size_t k = 0; k < mdata->num_children; k++) {
        const char *key = mdata->keys[k];
        if (strcmp(key, "steps") == 0 || strcmp(key, "_page") == 0)
            continue;
        if (!pf_json_same_value(&mdata->children[k], json_get(pdata, key)))
            return "a scalar field changed between pages";
    }
    return NULL;
}

/* Append the page's step rows into the merged doc's data.steps array. */
static void pf_paged_append_rows(struct json_value *doc_out,
                                 const struct json_value *psteps,
                                 size_t page_rows)
{
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

/* Fold one successfully-shaped page into doc_out: the first page moves
 * page_doc's ownership wholesale; later pages append their step rows and
 * free page_doc. */
static void pf_paged_fold_page(struct json_value *doc_out,
                               struct json_value *page_doc,
                               const struct json_value *psteps,
                               size_t page_rows, bool *merged)
{
    if (!*merged) {
        *doc_out = *page_doc;
        *merged = true;
        return;
    }
    pf_paged_append_rows(doc_out, psteps, page_rows);
    json_free(page_doc);
}

/* Final-page totals check: _page.total_items and data.step_count (when
 * present) must agree with the rows actually collected. */
static const char *pf_paged_totals_why(const struct json_value *doc_out,
                                       int64_t total, size_t collected)
{
    if (total < 0 || (size_t)total != collected)
        return "final _page.total_items disagrees with the rows";
    const struct json_value *scv =
        json_get(json_get(doc_out, "data"), "step_count");
    if (scv && json_get_int(scv) != (int64_t)collected)
        return "step_count disagrees with the paged rows";
    return NULL;
}

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
        if (!pf_paged_build_input(input, sizeof(input), id_key, id_val,
                                  datadir, cursor, command_words, error,
                                  error_cap))
            break;
        struct json_value page_doc;
        if (!pf_cli(bin_dir, NULL, command_words, input, &page_doc, error,
                    error_cap))
            break; /* pf_cli already logged */
        const struct json_value *pdata = json_get(&page_doc, "data");
        const struct json_value *psteps = json_get(pdata, "steps");
        const struct json_value *ppage = json_get(pdata, "_page");
        const char *why = pf_paged_shape_why(pdata, psteps, ppage, cursor,
                                             collected);
        /* Page metadata must be read before page_doc is folded or freed. */
        bool truncated = json_get_bool(json_get(ppage, "truncated"));
        int64_t total = json_get_int(json_get(ppage, "total_items"));
        int64_t next = pf_paged_next_cursor(ppage, truncated);
        size_t page_rows = psteps ? psteps->num_children : 0;
        if (!why)
            why = pf_paged_advance_why(truncated, page_rows, next, cursor);
        if (!why && merged)
            why = pf_paged_scalars_why(doc_out, pdata);
        if (!why)
            pf_paged_fold_page(doc_out, &page_doc, psteps, page_rows,
                               &merged);
        else
            json_free(&page_doc);
        collected += page_rows;
        if (!why && !truncated)
            why = pf_paged_totals_why(doc_out, total, collected);
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

/* Out-parameters threaded through the recursive fixed-layout scan. */
struct gate_walk_ctx {
    bool *has_license;
    bool *has_readme;
    bool *has_meta;
    unsigned *inc_h;
    unsigned *src_c;
    unsigned *test_c;
};

static bool gate_walk(const char *dir, size_t root_len,
                      struct gate_walk_ctx *ctx, char *error,
                      size_t error_cap);

/* Classify one accepted regular file (relative path) into the layout
 * counters — split out of gate_walk_entry to keep its own complexity down. */
static void gate_walk_classify(const char *rel, struct gate_walk_ctx *ctx)
{
    size_t rlen = strlen(rel);
    bool is_c = rlen >= 3 && strcmp(rel + rlen - 2, ".c") == 0;
    bool is_h = rlen >= 3 && strcmp(rel + rlen - 2, ".h") == 0;
    if (strcmp(rel, "LICENSE") == 0) *ctx->has_license = true;
    else if (strcmp(rel, "README") == 0 || strcmp(rel, "README.md") == 0)
        *ctx->has_readme = true;
    else if (strcmp(rel, "zcode-package.json") == 0) *ctx->has_meta = true;
    if (strncmp(rel, "include/", 8) == 0 && is_h) (*ctx->inc_h)++;
    if (strncmp(rel, "src/", 4) == 0 && is_c) (*ctx->src_c)++;
    if (strncmp(rel, "tests/", 6) == 0 && is_c) (*ctx->test_c)++;
}

/* One directory entry of gate_walk: build its path, lstat it, and dispatch
 * on what it is. Split out to keep gate_walk's own complexity down. */
static bool gate_walk_entry(const char *dir, size_t root_len,
                            const char *name, struct gate_walk_ctx *ctx,
                            char *error, size_t error_cap)
{
    size_t plen = strlen(dir) + strlen(name) + 2u;
    char *path = zcl_malloc(plen, "factory.gate.path");
    if (!path)
        LOG_FAIL(PF_LOG, "gate path alloc");
    (void)snprintf(path, plen, "%s/%s", dir, name);
    struct stat st;
    if (lstat(path, &st) != 0) {
        (void)snprintf(error, error_cap, "lstat %s: %s", path,
                       strerror(errno));
        LOG_ERROR(PF_LOG, "%s", error);
        free(path);
        return false;
    }
    if (S_ISLNK(st.st_mode)) {
        (void)snprintf(error, error_cap, "symlink refused: %s", path);
        LOG_ERROR(PF_LOG, "%s", error);
        free(path);
        return false;
    }
    if (S_ISDIR(st.st_mode)) {
        bool ok = gate_walk(path, root_len, ctx, error, error_cap);
        free(path);
        return ok;
    }
    if (!S_ISREG(st.st_mode)) {
        (void)snprintf(error, error_cap, "non-regular file refused: %s",
                       path);
        LOG_ERROR(PF_LOG, "%s", error);
        free(path);
        return false;
    }
    if ((uint64_t)st.st_size > VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES) {
        (void)snprintf(error, error_cap,
                       "file over the 64 MiB cap: %s", path);
        LOG_ERROR(PF_LOG, "%s", error);
        free(path);
        return false;
    }
    gate_walk_classify(path + root_len, ctx);
    free(path);
    return true;
}

/* Recursive fixed-layout scan: no symlinks or non-regular files, per-file
 * size under the 64 MiB cap, required layout entries present. */
static bool gate_walk(const char *dir, size_t root_len,
                      struct gate_walk_ctx *ctx, char *error,
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
        ok = gate_walk_entry(dir, root_len, ent->d_name, ctx, error,
                            error_cap);
    }
    closedir(d);
    return ok;
}

/* Fixed-layout walk plus completeness check: LICENSE, README,
 * zcode-package.json, at least one include-header, src-c and tests-c. */
static bool gate_check_layout(const char *dir, char *error, size_t error_cap)
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
    struct gate_walk_ctx ctx = {
        .has_license = &has_license, .has_readme = &has_readme,
        .has_meta = &has_meta, .inc_h = &inc_h, .src_c = &src_c,
        .test_c = &test_c,
    };
    bool ok = gate_walk(root, root_len + 1u, &ctx, error, error_cap);
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
    return true;
}

/* Read and JSON-parse zcode-package.json into info->meta. */
static bool gate_check_load_meta(const char *dir, struct gate_info *info,
                                 char *error, size_t error_cap)
{
    size_t plen = strlen(dir) + sizeof("/zcode-package.json");
    char *meta_path = zcl_malloc(plen, "factory.gate.meta");
    if (!meta_path)
        LOG_FAIL(PF_LOG, "meta path alloc");
    (void)snprintf(meta_path, plen, "%s/zcode-package.json", dir);
    uint8_t *bytes = NULL;
    size_t blen = 0;
    bool ok = pf_read_file(meta_path, PF_META_MAX_BYTES, &bytes, &blen);
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
    return true;
}

/* Validate name/semver/license, copy them into info, and check the SPDX
 * allowlist. */
static bool gate_check_meta_fields(struct gate_info *info, char *error,
                                   size_t error_cap)
{
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
    return true;
}

/* No placeholder dep roots: every dependency's 64-hex root must decode and
 * be non-zero. */
static bool gate_check_deps(struct gate_info *info, char *error,
                            size_t error_cap)
{
    const struct json_value *deps = json_get(&info->meta, "dependencies");
    if (!deps || deps->type != JSON_ARR)
        return true;
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
    return true;
}

static bool gate_check(const char *dir, struct gate_info *info, char *error,
                       size_t error_cap)
{
    if (!gate_check_layout(dir, error, error_cap))
        return false;
    if (!gate_check_load_meta(dir, info, error, error_cap))
        return false;
    if (!gate_check_meta_fields(info, error, error_cap))
        return false;
    return gate_check_deps(info, error, error_cap);
}

/* ── pin-dep ──────────────────────────────────────────────────────── */

/* Locate the "dependencies" array's open bracket, or SIZE_MAX. */
static size_t pin_dep_find_array(const char *text, size_t len)
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
            if (j < len && text[j] == '[')
                return j;
        }
    }
    return SIZE_MAX;
}

/* String-aware matching close brace for the object starting at obj_start,
 * or SIZE_MAX if unbalanced within [obj_start, len). */
static size_t pin_dep_find_obj_end(const char *text, size_t obj_start,
                                   size_t len)
{
    int depth = 0;
    bool in_str = false, esc = false;
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
            if (depth == 0)
                return j;
        }
    }
    return SIZE_MAX;
}

/* Scan one JSON string starting at text[*pos] == '"'. Advances *pos past
 * the closing quote and returns the content span [*s0, *s1). */
static void pin_dep_scan_str(const char *text, size_t bound, size_t *pos,
                             size_t *s0, size_t *s1)
{
    size_t j = ++(*pos);
    bool e = false;
    while (j < bound && (text[j] != '"' || e)) {
        if (e) e = false;
        else if (text[j] == '\\') e = true;
        j++;
    }
    *s0 = *pos;
    *s1 = j;
    *pos = j + 1;
}

/* Does the string span [s0, s1) equal `key` exactly? */
static bool pin_dep_key_is(const char *text, size_t s0, size_t s1,
                           const char *key)
{
    size_t klen = strlen(key);
    return (s1 - s0) == klen && memcmp(text + s0, key, klen) == 0;
}

/* A JSON key ends at k (index of ':' or the char after the key string,
 * skipping whitespace). Scan the string value that follows it, if any. */
static bool pin_dep_scan_value(const char *text, size_t obj_end, size_t k,
                               size_t *v0, size_t *v1)
{
    size_t v = k + 1;
    while (v < obj_end && isspace((unsigned char)text[v])) v++;
    if (v >= obj_end || text[v] != '"')
        return false;
    pin_dep_scan_str(text, obj_end, &v, v0, v1);
    return true;
}

/* Within [obj_start, obj_end): does a "name" string equal dep_name?
 * Record the "root" value span. */
static void pin_dep_scan_obj_fields(const char *text, size_t obj_start,
                                    size_t obj_end, const char *dep_name,
                                    bool *name_match, size_t *root_vs,
                                    size_t *root_ve)
{
    size_t j = obj_start;
    while (j < obj_end) {
        if (text[j] != '"') {
            j++;
            continue;
        }
        size_t s0, s1;
        pin_dep_scan_str(text, obj_end, &j, &s0, &s1);
        size_t k = j;
        while (k < obj_end && isspace((unsigned char)text[k])) k++;
        bool is_key = k < obj_end && text[k] == ':';
        if (is_key && pin_dep_key_is(text, s0, s1, "name")) {
            size_t v0, v1;
            if (pin_dep_scan_value(text, obj_end, k, &v0, &v1) &&
                (size_t)(v1 - v0) == strlen(dep_name) &&
                memcmp(text + v0, dep_name, strlen(dep_name)) == 0)
                *name_match = true;
        } else if (is_key && pin_dep_key_is(text, s0, s1, "root")) {
            size_t v0, v1;
            if (pin_dep_scan_value(text, obj_end, k, &v0, &v1)) {
                *root_vs = v0;
                *root_ve = v1;
            }
        }
    }
}

enum pin_dep_next { PIN_DEP_OBJ, PIN_DEP_ARR_END, PIN_DEP_BAD_ELEM };

/* Skip whitespace and element separators to the next array element;
 * report whether it is an object, the array's close, or malformed. */
static enum pin_dep_next pin_dep_skip_to_obj(const char *text, size_t len,
                                             size_t *i)
{
    while (*i < len && (isspace((unsigned char)text[*i]) || text[*i] == ','))
        (*i)++;
    if (*i >= len || text[*i] == ']')
        return PIN_DEP_ARR_END;
    if (text[*i] != '{')
        return PIN_DEP_BAD_ELEM;
    return PIN_DEP_OBJ;
}

/* Walk the "dependencies" array elements at depth 1, tracking string
 * state, looking for the unique object whose "name" equals dep_name. */
static bool pin_dep_walk_array(const char *text, size_t len, size_t arr,
                               const char *dep_name, size_t *val_start,
                               size_t *val_end, char *error,
                               size_t error_cap)
{
    size_t name_hits = 0;
    size_t i = arr + 1u;
    bool ok = false;
    while (i < len && !ok) {
        enum pin_dep_next nx = pin_dep_skip_to_obj(text, len, &i);
        if (nx == PIN_DEP_ARR_END) break;
        if (nx == PIN_DEP_BAD_ELEM) {
            (void)snprintf(error, error_cap,
                           "dependencies element is not an object");
            LOG_ERROR(PF_LOG, "pin-dep: %s", error);
            return false;
        }
        size_t obj_start = i;
        size_t obj_end = pin_dep_find_obj_end(text, obj_start, len);
        if (obj_end == SIZE_MAX) {
            (void)snprintf(error, error_cap, "unbalanced dependency object");
            LOG_ERROR(PF_LOG, "pin-dep: %s", error);
            return false;
        }
        bool name_match = false;
        size_t root_vs = SIZE_MAX, root_ve = SIZE_MAX;
        pin_dep_scan_obj_fields(text, obj_start, obj_end, dep_name,
                                &name_match, &root_vs, &root_ve);
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

/* Byte scanner over JSON text: tracks string state and {} depth. Finds the
 * "dependencies" array, then the object element whose "name" string equals
 * dep_name, then the "root" string INSIDE that same object span. Returns
 * the value span (64 chars) via [val_start, val_end). */
static bool pin_dep_locate(const char *text, size_t len, const char *dep_name,
                           size_t *val_start, size_t *val_end,
                           char *error, size_t error_cap)
{
    size_t arr = pin_dep_find_array(text, len);
    if (arr == SIZE_MAX) {
        (void)snprintf(error, error_cap, "no dependencies array found");
        LOG_ERROR(PF_LOG, "pin-dep: %s", error);
        return false;
    }
    return pin_dep_walk_array(text, len, arr, dep_name, val_start, val_end,
                              error, error_cap);
}

static bool pin_dep_valid_root(const char *dep_name, const char *dep_root,
                               uint8_t raw[32])
{
    return dep_name && *dep_name && dep_root && strlen(dep_root) == 64 &&
           zcl_hex_decode_lower(dep_root, raw, 32) && !root_zero(raw);
}

/* Locate the dependency's root value, refuse unless it is still the
 * all-zero placeholder, and rewrite the file in place (same length, only
 * the 64 root chars change). */
static bool pin_dep_rewrite_file(const char *path, uint8_t *text, size_t len,
                                 const char *dep_name, const char *dep_root,
                                 char *error, size_t error_cap)
{
    size_t vs = 0, ve = 0;
    if (!pin_dep_locate((const char *)text, len, dep_name, &vs, &ve, error,
                        error_cap))
        return false;
    char cur_hex[65];
    memcpy(cur_hex, text + vs, 64);
    cur_hex[64] = '\0';
    uint8_t cur[32];
    if (!zcl_hex_decode_lower(cur_hex, cur, 32) || !root_zero(cur)) {
        LOG_ERROR(PF_LOG,
                  "dependency %s is already pinned (no placeholder); "
                  "refusing to replace a real root", dep_name);
        return false;
    }
    struct buf out = {0};
    bool ok = buf_put(&out, text, vs) && buf_put(&out, dep_root, 64) &&
             buf_put(&out, text + ve, len - ve);
    if (ok) ok = pf_write_atomic(path, out.p, out.len);
    buf_free(&out);
    return ok;
}

/* Re-parse the rewritten file and confirm the pin landed exactly. */
static bool pin_dep_verify(const char *path, const char *dep_name,
                           const char *dep_root)
{
    uint8_t *check = NULL;
    size_t clen = 0;
    if (!pf_read_file(path, PF_META_MAX_BYTES, &check, &clen))
        return false;
    struct json_value doc;
    json_init(&doc);
    bool parsed = json_read(&doc, (const char *)check, clen);
    free(check);
    if (!parsed) {
        json_free(&doc);
        LOG_ERROR(PF_LOG, "rewritten %s no longer parses", path);
        return false;
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
    return confirmed;
}

static int cmd_pin_dep(const char *dir, const char *dep_name,
                       const char *dep_root)
{
    uint8_t raw[32];
    if (!pin_dep_valid_root(dep_name, dep_root, raw))
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
    bool ok = pin_dep_rewrite_file(path, text, len, dep_name, dep_root,
                                   error, sizeof(error));
    free(text);
    if (!ok) {
        free(path);
        return 1;
    }
    if (!pin_dep_verify(path, dep_name, dep_root)) {
        free(path);
        LOG_ERR(PF_LOG, "pin verification failed for %s", dep_name);
    }
    printf("pin-dep: %s dependencies[%s].root = %s\n", path, dep_name,
           dep_root);
    free(path);
    return 0;
}

/* ── admission signing seed (the census signer seed convention) ────── */

/* Load an existing 32-raw-byte seed from an already-open fd (closes it). */
static bool pf_seed_load(int fd, const char *path, uint8_t seed[32])
{
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

/* Ensure the seed file's parent directory exists. */
static bool pf_seed_mkdir_for(const char *path)
{
    const char *slash = strrchr(path, '/');
    if (!slash)
        LOG_FAIL(PF_LOG, "signer seed path %s has no directory", path);
    size_t dir_len = (size_t)(slash - path);
    char *dir = zcl_malloc(dir_len + 1u, "factory.seed.dir");
    if (!dir)
        LOG_FAIL(PF_LOG, "seed dir alloc");
    memcpy(dir, path, dir_len);
    dir[dir_len] = '\0';
    bool ok = pf_mkdir_p(dir);
    free(dir);
    return ok;
}

/* Generate a fresh 32-byte seed and write it to a brand-new file. */
static bool pf_seed_create(const char *path, uint8_t seed[32])
{
    if (!pf_seed_mkdir_for(path))
        return false;
    if (!rng_fill(seed, 32))
        LOG_FAIL(PF_LOG, "kernel CSPRNG refused 32 bytes");
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
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

static bool pf_seed_load_or_create(const char *path, uint8_t seed[32])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0)
        return pf_seed_load(fd, path, seed);
    if (errno != ENOENT)
        LOG_FAIL(PF_LOG, "open signer seed %s: %s", path, strerror(errno));
    return pf_seed_create(path, seed);
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

/* Work dir under the system temp for factory_second_receipt's confined
 * rebuild, removed at the end by the caller. */
static bool fsr_make_work_dir(char work[512])
{
    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir) tmpdir = "/tmp";
    if (snprintf(work, 512, "%s/package-factory-emit-XXXXXX", tmpdir) >= 512)
        LOG_FAIL(PF_LOG, "emit work path overflow");
    if (!mkdtemp(work))
        LOG_FAIL(PF_LOG, "mkdtemp under %s: %s", tmpdir, strerror(errno));
    return true;
}

/* Derive recipe_path/emit_dir under work, write the recipe wire there, and
 * resolve the package's absolute source path. */
static bool fsr_prepare_paths(const char *work, char *recipe_path,
                              size_t recipe_path_cap, char *emit_dir,
                              size_t emit_dir_cap, const uint8_t *recipe_wire,
                              size_t recipe_wire_len, const char *package_dir,
                              char *pkg_abs, char *error, size_t error_cap)
{
    if (snprintf(recipe_path, recipe_path_cap, "%s/recipe.wire", work) >=
            (int)recipe_path_cap ||
        snprintf(emit_dir, emit_dir_cap, "%s/emit", work) >=
            (int)emit_dir_cap)
        LOG_FAIL(PF_LOG, "emit path overflow");
    if (!pf_write_atomic(recipe_path, recipe_wire, recipe_wire_len))
        return false;
    if (!realpath(package_dir, pkg_abs)) {
        (void)snprintf(error, error_cap, "realpath %s: %s", package_dir,
                       strerror(errno));
        LOG_ERROR(PF_LOG, "%s", error);
        return false;
    }
    return true;
}

/* The install receipt is read FIRST: its committed dependency set is the
 * exact, install-time-validated input list the standard-profile rebuild
 * must be fed. The quick path commits the declared DIRECT deps
 * (pkgl_receipt_inputs_match enforces this at install time); the plan's
 * transitive closure is a superset and must NOT be used — the worker
 * records every --dep it is handed, so feeding the closure would
 * mis-record transitive roots and fail reproduction. */
static bool fsr_read_reference(const char *store,
                               const char *reference_receipt_hex,
                               uint8_t **ref_wire, size_t *ref_len,
                               struct vcs_package_build_receipt *reference,
                               char *error, size_t error_cap)
{
    char ref_path[PF_PATH_CAP];
    if (snprintf(ref_path, sizeof(ref_path), "%s/zcode/receipts/%s", store,
                reference_receipt_hex) >= (int)sizeof(ref_path))
        LOG_FAIL(PF_LOG, "reference receipt path overflow");
    if (!pf_read_file(ref_path, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES, ref_wire,
                      ref_len)) {
        (void)snprintf(error, error_cap, "install receipt %s unreadable",
                       reference_receipt_hex);
        return false;
    }
    if (vcs_package_build_parse(*ref_wire, *ref_len, reference) !=
            VCS_PACKAGE_BUILD_OK) {
        (void)snprintf(error, error_cap, "install receipt does not parse");
        return false;
    }
    return true;
}

/* The package name comes from the plan's target (last) step. */
static const char *fsr_resolve_pkg_name(const struct json_value *plan_steps)
{
    size_t step_count = 0;
    if (plan_steps && plan_steps->type == JSON_ARR)
        step_count = plan_steps->num_children;
    if (!step_count)
        return NULL;
    const struct json_value *target = json_at(plan_steps, step_count - 1u);
    return json_get_str(json_get(target, "name"));
}

/* Fixed (non-dependency) argv strings for the standard-profile verifier
 * spawn. */
struct fsr_verify_args {
    char bin[PF_PATH_CAP];
    char source_arg[PF_PATH_CAP + 32];
    char recipe_arg[664];
    char emit_arg[664];
    char lock_arg[96];
    char name_arg[VCS_PACKAGE_RELEASE_NAME_MAX + 32];
    char fast_arg[PF_PATH_CAP + 16];
    bool use_fast;
};

static bool fsr_build_fixed_args(struct fsr_verify_args *fa,
                                 const struct run_args *args,
                                 const char *pkg_abs, const char *recipe_path,
                                 const char *emit_dir, const char *lock_hex,
                                 const char *pkg_name)
{
    if (snprintf(fa->bin, sizeof(fa->bin), "%s/zclassic23-package-verify",
                args->bin_dir) >= (int)sizeof(fa->bin))
        LOG_FAIL(PF_LOG, "verifier path overflow");
    if (snprintf(fa->source_arg, sizeof(fa->source_arg),
                "--zbuild-package-source=%s", pkg_abs) >=
                (int)sizeof(fa->source_arg) ||
        snprintf(fa->recipe_arg, sizeof(fa->recipe_arg),
                "--zbuild-package-recipe=%s", recipe_path) >=
                (int)sizeof(fa->recipe_arg) ||
        snprintf(fa->emit_arg, sizeof(fa->emit_arg), "--emit=%s", emit_dir) >=
                (int)sizeof(fa->emit_arg) ||
        snprintf(fa->lock_arg, sizeof(fa->lock_arg), "--lock-root=%s",
                lock_hex) >= (int)sizeof(fa->lock_arg))
        LOG_FAIL(PF_LOG, "verifier arg overflow");
    if (!pkg_name)
        LOG_FAIL(PF_LOG, "add plan carried no target package name");
    if (snprintf(fa->name_arg, sizeof(fa->name_arg),
                "--zbuild-package-name=%s", pkg_name) >=
            (int)sizeof(fa->name_arg))
        LOG_FAIL(PF_LOG, "name arg overflow");
    fa->use_fast = args->fast_cache_dir != NULL;
    if (fa->use_fast &&
        snprintf(fa->fast_arg, sizeof(fa->fast_arg), "--fast-cache=%s",
                args->fast_cache_dir) >= (int)sizeof(fa->fast_arg))
        LOG_FAIL(PF_LOG, "fast-cache arg overflow");
    return true;
}

/* Dep argv comes from the reference (install) receipt's committed set —
 * never from the plan's transitive closure (see fsr_read_reference). */
static bool fsr_build_dep_args(const struct vcs_package_build_receipt *reference,
                               const char *store, size_t dep_stride,
                               char **dep_args_out)
{
    size_t dep_count = reference->dep_count;
    *dep_args_out = NULL;
    if (!dep_count)
        return true;
    char *dep_args = zcl_malloc(dep_stride * dep_count, "factory.depargs");
    if (!dep_args)
        LOG_FAIL(PF_LOG, "dep args alloc");
    for (size_t i = 0; i < dep_count; i++) {
        char droot[65];
        pf_root_hex(reference->dep_roots[i], droot);
        if (snprintf(dep_args + i * dep_stride, dep_stride,
                     "--dep=%s,%s/zcode/installed/%s", droot, store,
                     droot) >= (int)dep_stride)
            LOG_FAIL(PF_LOG, "dep arg overflow");
    }
    *dep_args_out = dep_args;
    return true;
}

/* argv: verifier <root> --zbuild-package-source=<abs pkg>
 * --zbuild-package-recipe=<file> --zbuild-package-name=<name>
 * --zbuild-package-profile=standard --zbuild-package-max-cpu-..
 * --emit=<dir> --lock-root=<hex> [--dep=<root>,<dir>]...
 * --require-full-isolation */
static bool fsr_run_verifier(const char *root_hex,
                             const struct fsr_verify_args *fa,
                             char *dep_args, size_t dep_count,
                             size_t dep_stride, struct pf_fast_stats *fast,
                             int *rc_out, char *error, size_t error_cap)
{
    const char *argv[13u + VCS_PACKAGE_BUILD_MAX_DEPS];
    size_t argc = 0;
    argv[argc++] = fa->bin;
    argv[argc++] = root_hex;
    argv[argc++] = fa->source_arg;
    argv[argc++] = fa->recipe_arg;
    argv[argc++] = fa->name_arg;
    argv[argc++] = "--zbuild-package-profile=standard";
    argv[argc++] = "--zbuild-package-max-cpu-seconds=120";
    argv[argc++] = fa->emit_arg;
    argv[argc++] = fa->lock_arg;
    for (size_t i = 0; i < dep_count; i++)
        argv[argc++] = dep_args + i * dep_stride;
    if (fa->use_fast)
        argv[argc++] = fa->fast_arg;
    argv[argc++] = "--require-full-isolation";
    argv[argc] = NULL;
    char *vout = zcl_malloc(PF_CLI_STDOUT_CAP, "factory.verify.out");
    if (!vout)
        LOG_FAIL(PF_LOG, "verifier stdout alloc");
    *rc_out = pf_spawn((char *const *)argv, NULL, 0, vout, PF_CLI_STDOUT_CAP);
    if (fast)
        pf_fast_stats_consume(fast, vout);
    if (*rc_out != 0) {
        char *nl = strchr(vout, '\n');
        if (nl) *nl = '\0';
        (void)snprintf(error, error_cap,
                       "standard-profile rebuild exit %d%s%s", *rc_out,
                       vout[0] ? ": " : "", vout);
        LOG_ERROR(PF_LOG, "%s", error);
    }
    free(vout);
    return true;
}

/* Build every verifier argv piece and spawn it. */
static bool fsr_verify_stage(const struct run_args *args, const char *store,
                             const char *root_hex, const char *lock_hex,
                             const struct json_value *plan_steps,
                             const char *pkg_abs, const char *recipe_path,
                             const char *emit_dir,
                             const struct vcs_package_build_receipt *reference,
                             struct pf_fast_stats *fast, int *rc_out,
                             char *error, size_t error_cap)
{
    struct fsr_verify_args fa = {0};
    const char *pkg_name = fsr_resolve_pkg_name(plan_steps);
    if (!fsr_build_fixed_args(&fa, args, pkg_abs, recipe_path, emit_dir,
                              lock_hex, pkg_name))
        return false;
    size_t dep_stride = PF_PATH_CAP + 96u;
    char *dep_args = NULL;
    bool ok = fsr_build_dep_args(reference, store, dep_stride, &dep_args);
    if (ok)
        ok = fsr_run_verifier(root_hex, &fa, dep_args, reference->dep_count,
                              dep_stride, fast, rc_out, error, error_cap);
    free(dep_args);
    return ok;
}

/* Read + compare + file the second receipt. */
static bool fsr_check_reproduction(const char *store,
                                   const struct vcs_package_build_receipt *reference,
                                   const char *reference_receipt_hex,
                                   const char *emit_dir,
                                   struct store_result *sr, char *error,
                                   size_t error_cap)
{
    char report_path[664];
    if (snprintf(report_path, sizeof(report_path), "%s/build-report",
                emit_dir) >= (int)sizeof(report_path))
        LOG_FAIL(PF_LOG, "report path overflow");
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (!pf_read_file(report_path, VCS_PACKAGE_BUILD_MAX_WIRE_BYTES, &wire,
                      &wire_len)) {
        (void)snprintf(error, error_cap, "no build-report emitted");
        return false;
    }
    struct vcs_package_build_receipt rebuild;
    if (vcs_package_build_parse(wire, wire_len, &rebuild) !=
            VCS_PACKAGE_BUILD_OK) {
        (void)snprintf(error, error_cap, "emitted receipt invalid");
        free(wire);
        return false;
    }
    uint8_t rebuild_id[32];
    if (vcs_package_build_id(&rebuild, rebuild_id) != VCS_PACKAGE_BUILD_OK) {
        (void)snprintf(error, error_cap, "receipt id failed");
        free(wire);
        return false;
    }
    /* The reference receipt was read + parsed before the spawn; compare
     * against that pre-validated copy directly. */
    struct vcs_reproduce_verdict verdict;
    vcs_package_reproduce_compare(reference, &rebuild, &verdict);
    if (!verdict.reproduced) {
        (void)snprintf(error, error_cap,
            "standard-profile rebuild does NOT reproduce the "
            "install build: %s %s",
            vcs_reproduce_rule_string((enum vcs_reproduce_rule)verdict.rule),
            verdict.detail);
        LOG_ERROR(PF_LOG, "%s", error);
        free(wire);
        return false;
    }
    pf_root_hex(rebuild_id, sr->receipt_standard);
    if (strcmp(sr->receipt_standard, reference_receipt_hex) == 0) {
        (void)snprintf(error, error_cap,
            "receipt-not-distinct: the second build filed "
            "the same receipt id");
        LOG_ERROR(PF_LOG, "%s", error);
        free(wire);
        return false;
    }
    char dest[PF_PATH_CAP];
    if (snprintf(dest, sizeof(dest), "%s/zcode/receipts/%s", store,
                sr->receipt_standard) >= (int)sizeof(dest))
        LOG_FAIL(PF_LOG, "receipt dest overflow");
    bool ok = pf_write_atomic(dest, wire, wire_len);
    if (!ok)
        (void)snprintf(error, error_cap, "cannot file the second receipt");
    free(wire);
    return ok;
}

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
    if (!fsr_make_work_dir(work))
        return false;
    char recipe_path[600], emit_dir[600], pkg_abs[PF_PATH_CAP];
    bool ok = fsr_prepare_paths(work, recipe_path, sizeof(recipe_path),
                                emit_dir, sizeof(emit_dir), recipe_wire,
                                recipe_wire_len, args->package_dir, pkg_abs,
                                error, error_cap);
    uint8_t *ref_wire = NULL;
    size_t ref_len = 0;
    struct vcs_package_build_receipt reference;
    if (ok)
        ok = fsr_read_reference(store, reference_receipt_hex, &ref_wire,
                                &ref_len, &reference, error, error_cap);
    int rc = -1;
    if (ok)
        ok = fsr_verify_stage(args, store, root_hex, lock_hex, plan_steps,
                              pkg_abs, recipe_path, emit_dir, &reference,
                              fast, &rc, error, error_cap);
    if (ok && rc != 0) ok = false;
    if (ok)
        ok = fsr_check_reproduction(store, &reference, reference_receipt_hex,
                                    emit_dir, sr, error, error_cap);
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

/* Fields shared by every stage of one store's journey. */
struct fsj_ctx {
    const struct run_args *args;
    const char *store;
    struct pf_report *rep;
    const char *tag;
    struct store_result *sr;
};

/* Format the "publish plan not valid" refusal, leading with the first
 * failed rule (the reply carries the exact failed rules; "blocked" alone
 * is undiagnosable from the report). */
static void fsj_format_publish_plan_error(const struct json_value *doc,
                                          char *error, size_t error_cap)
{
    const struct json_value *data = json_get(doc, "data");
    const char *readiness = json_get_str(json_get(data, "readiness"));
    const char *next_action = json_get_str(json_get(data, "next_action"));
    const struct json_value *failures = json_get(data, "failures");
    const char *frule = NULL, *fdetail = NULL;
    if (failures && failures->type == JSON_ARR && failures->num_children) {
        const struct json_value *f0 = &failures->children[0];
        frule = json_get_str(json_get(f0, "rule"));
        fdetail = json_get_str(json_get(f0, "detail"));
    }
    (void)snprintf(error, error_cap,
                   "publish plan not valid (readiness=%s next=%s%s%s%s%s)",
                   readiness ? readiness : "?",
                   next_action ? next_action : "?",
                   frule ? " first=" : "", frule ? frule : "",
                   fdetail ? ": " : "", fdetail ? fdetail : "");
}

static bool fsj_publish_plan(const struct fsj_ctx *ctx,
                             const char *release_hex,
                             const char *manifest_hex,
                             const char *recipe_hex, char *input,
                             char *error, size_t error_cap)
{
    char name[48];
    (void)snprintf(name, sizeof(name), "publish_plan_%s", ctx->tag);
    struct pf_step *s = pf_step_begin(ctx->rep, name);
    uint64_t t0 = now_ms();
    int n = snprintf(input, PF_CLI_STDOUT_CAP,
        "{\"release_hex\":\"%s\",\"manifest_hex\":\"%s\","
        "\"recipe_hex\":\"%s\",\"dir\":\"%s\",\"datadir\":\"%s\"}",
        release_hex, manifest_hex, recipe_hex, ctx->args->package_dir,
        ctx->store);
    if (n <= 0 || (size_t)n >= PF_CLI_STDOUT_CAP)
        return pf_step_fail(ctx->rep, s, t0, "publish input overflow");
    struct json_value doc;
    if (!pf_cli(ctx->args->bin_dir, NULL, "zcode package publish plan",
                input, &doc, error, error_cap))
        return pf_step_fail(ctx->rep, s, t0, error);
    const struct json_value *valid =
        json_get(json_get(&doc, "data"), "valid");
    bool v = valid && json_get_bool(valid);
    if (!v)
        fsj_format_publish_plan_error(&doc, error, error_cap);
    json_free(&doc);
    if (!v)
        return pf_step_fail(ctx->rep, s, t0, error);
    pf_step_ok(s, t0);
    return true;
}

static bool fsj_publish_commit(const struct fsj_ctx *ctx,
                               const char *release_hex,
                               const char *manifest_hex,
                               const char *recipe_hex, char *input,
                               char *error, size_t error_cap)
{
    char name[48];
    (void)snprintf(name, sizeof(name), "publish_commit_%s", ctx->tag);
    struct pf_step *s = pf_step_begin(ctx->rep, name);
    uint64_t t0 = now_ms();
    int n = snprintf(input, PF_CLI_STDOUT_CAP,
        "{\"release_hex\":\"%s\",\"manifest_hex\":\"%s\","
        "\"recipe_hex\":\"%s\",\"dir\":\"%s\",\"datadir\":\"%s\"}",
        release_hex, manifest_hex, recipe_hex, ctx->args->package_dir,
        ctx->store);
    if (n <= 0 || (size_t)n >= PF_CLI_STDOUT_CAP)
        return pf_step_fail(ctx->rep, s, t0, "publish input overflow");
    struct json_value doc;
    if (!pf_cli(ctx->args->bin_dir, NULL, "zcode package publish commit",
                input, &doc, error, error_cap))
        return pf_step_fail(ctx->rep, s, t0, error);
    const char *result =
        json_get_str(json_get(json_get(&doc, "data"), "result"));
    bool okr = result && (strcmp(result, "committed") == 0 ||
                          strcmp(result, "published") == 0 ||
                          strcmp(result, "duplicate") == 0);
    json_free(&doc);
    if (!okr)
        return pf_step_fail(ctx->rep, s, t0, "publish commit result bad");
    ctx->sr->publish_ok = true;
    pf_step_ok(s, t0);
    return true;
}

/* A dependency-rich plan overflows the bounded reply envelope, so the
 * fetch pages through the steps array and reassembles it. */
static bool fsj_add_plan(const struct fsj_ctx *ctx, const char *root_hex,
                         struct json_value *plan_doc,
                         const struct json_value **steps_out,
                         char lock_hex[65], char *error, size_t error_cap)
{
    char name[48];
    (void)snprintf(name, sizeof(name), "add_plan_%s", ctx->tag);
    struct pf_step *s = pf_step_begin(ctx->rep, name);
    uint64_t t0 = now_ms();
    if (!pf_cli_paged_steps(ctx->args->bin_dir, "zcode package add plan",
                            "name_or_root", root_hex, ctx->store, plan_doc,
                            error, error_cap)) {
        json_free(plan_doc);
        return pf_step_fail(ctx->rep, s, t0, error);
    }
    const struct json_value *data = json_get(plan_doc, "data");
    const char *plan_id = json_get_str(json_get(data, "plan_id"));
    const char *lk = json_get_str(json_get(data, "lock_root"));
    const struct json_value *ready = json_get(data, "ready");
    const struct json_value *steps = json_get(data, "steps");
    *steps_out = steps;
    if (!plan_id || strlen(plan_id) != 64 || !lk || strlen(lk) != 64 ||
        !ready || !json_get_bool(ready) || !steps ||
        steps->type != JSON_ARR || !steps->num_children) {
        json_free(plan_doc);
        return pf_step_fail(ctx->rep, s, t0, "add plan not ready");
    }
    (void)snprintf(ctx->sr->plan_id, sizeof(ctx->sr->plan_id), "%s",
                   plan_id);
    (void)snprintf(lock_hex, 65, "%s", lk);
    pf_step_ok(s, t0);
    return true;
}

/* The commit step list mirrors the plan's, so it can overflow the bounded
 * reply envelope for a dependency-rich plan; page it the same way. */
static bool fsj_add_commit(const struct fsj_ctx *ctx,
                           struct json_value *plan_doc, char *error,
                           size_t error_cap)
{
    char name[48];
    (void)snprintf(name, sizeof(name), "add_commit_%s", ctx->tag);
    struct pf_step *s = pf_step_begin(ctx->rep, name);
    uint64_t t0 = now_ms();
    struct json_value doc;
    if (!pf_cli_paged_steps(ctx->args->bin_dir, "zcode package add commit",
                            "plan_id", ctx->sr->plan_id, ctx->store, &doc,
                            error, error_cap)) {
        json_free(plan_doc);
        return pf_step_fail(ctx->rep, s, t0, error);
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
        (void)snprintf(ctx->sr->receipt_quick, sizeof(ctx->sr->receipt_quick),
                      "%s", receipt);
    json_free(&doc);
    if (!oki) {
        json_free(plan_doc);
        return pf_step_fail(ctx->rep, s, t0,
                            "add commit did not install with a receipt");
    }
    ctx->sr->add_ok = true;
    pf_step_ok(s, t0);
    return true;
}

/* Second, distinct confined build receipt (factory_second_receipt). */
static bool fsj_second_receipt_step(const struct fsj_ctx *ctx,
                                    const char *root_hex,
                                    const char *lock_hex,
                                    const struct json_value *steps,
                                    const uint8_t *recipe_wire,
                                    size_t recipe_wire_len,
                                    struct json_value *plan_doc,
                                    struct pf_fast_stats *fast, char *error,
                                    size_t error_cap)
{
    char name[48];
    (void)snprintf(name, sizeof(name), "reproduce_build_%s", ctx->tag);
    struct pf_step *s = pf_step_begin(ctx->rep, name);
    uint64_t t0 = now_ms();
    bool ok2 = factory_second_receipt(
        ctx->args, ctx->store, root_hex, lock_hex, steps, recipe_wire,
        recipe_wire_len, ctx->sr->receipt_quick, ctx->sr, fast, error,
        error_cap);
    json_free(plan_doc);
    if (!ok2)
        return pf_step_fail(ctx->rep, s, t0, error);
    pf_step_ok(s, t0);
    return true;
}

/* Approved-verifier allowlist (local config; the publisher key) so `zcode
 * package verify` can run; the quorum is NOT reached without attestations
 * — only the reproduction verdict matters here. */
static bool fsj_write_approved_verifiers(const char *store,
                                         const char *publisher_pubkey)
{
    char av_path[PF_PATH_CAP];
    if (snprintf(av_path, sizeof(av_path), "%s/zcode/approved_verifiers",
                store) >= (int)sizeof(av_path)) {
        LOG_ERROR(PF_LOG, "approved_verifiers path overflow");
        return false;
    }
    if (access(av_path, R_OK) == 0)
        return true;
    char line[70];
    int n = snprintf(line, sizeof(line), "%s\n", publisher_pubkey);
    if (n <= 0 ||
        !pf_write_atomic(av_path, (const uint8_t *)line, (size_t)n)) {
        LOG_ERROR(PF_LOG, "cannot write %s", av_path);
        return false;
    }
    return true;
}

/* verify: require reproduced=true */
static bool fsj_verify_step(const struct fsj_ctx *ctx, const char *root_hex,
                            char *input, char *error, size_t error_cap)
{
    char name[48];
    (void)snprintf(name, sizeof(name), "verify_%s", ctx->tag);
    struct pf_step *s = pf_step_begin(ctx->rep, name);
    uint64_t t0 = now_ms();
    int n = snprintf(input, PF_CLI_STDOUT_CAP,
                     "{\"root\":\"%s\",\"datadir\":\"%s\"}", root_hex,
                     ctx->store);
    if (n <= 0 || (size_t)n >= PF_CLI_STDOUT_CAP)
        return pf_step_fail(ctx->rep, s, t0, "verify input overflow");
    struct json_value doc;
    if (!pf_cli(ctx->args->bin_dir, NULL, "zcode package verify", input,
                &doc, error, error_cap))
        return pf_step_fail(ctx->rep, s, t0, error);
    const struct json_value *repro = json_get(
        json_get(json_get(&doc, "data"), "reproduction"), "reproduced");
    ctx->sr->reproduced = repro && json_get_bool(repro);
    json_free(&doc);
    if (!ctx->sr->reproduced)
        return pf_step_fail(ctx->rep, s, t0,
                            "reproduction verdict is not reproduced");
    ctx->sr->verify_ok = true;
    pf_step_ok(s, t0);
    return true;
}

/* Second half of storage_ack: attempt the commit leg once a plan_token
 * came back. */
static bool fsj_storage_ack_commit(const struct fsj_ctx *ctx,
                                   const char *root_hex, const char *flag,
                                   const char *token, char *input,
                                   char *error, size_t error_cap)
{
    int n = snprintf(input, PF_CLI_STDOUT_CAP,
        "{\"mode\":\"commit\",\"namespace\":\"commons\","
        "\"transport_root\":\"%s\",\"sequence\":1,"
        "\"not_before\":1,\"expiry\":2,\"plan_token\":\"%s\"}",
        root_hex, token);
    if (n <= 0 || (size_t)n >= PF_CLI_STDOUT_CAP)
        return false;
    struct json_value doc;
    if (!pf_cli(ctx->args->bin_dir, flag, "zcode network storage_ack",
                input, &doc, error, error_cap))
        return false;
    json_free(&doc);
    return true;
}

/* storage_ack: attempt plan/commit offline; refusal is expected without
 * the live DHT service and is recorded, never fatal. */
static bool fsj_storage_ack_step(const struct fsj_ctx *ctx,
                                 const char *root_hex, char *input,
                                 char *error, size_t error_cap)
{
    char name[48];
    (void)snprintf(name, sizeof(name), "storage_ack_%s", ctx->tag);
    struct pf_step *s = pf_step_begin(ctx->rep, name);
    uint64_t t0 = now_ms();
    char flag[PF_PATH_CAP + 16];
    if (snprintf(flag, sizeof(flag), "-datadir=%s", ctx->store) >=
        (int)sizeof(flag)) {
        LOG_ERROR(PF_LOG, "datadir flag overflow");
        return false;
    }
    int n = snprintf(input, PF_CLI_STDOUT_CAP,
        "{\"mode\":\"plan\",\"namespace\":\"commons\","
        "\"transport_root\":\"%s\",\"sequence\":1,\"not_before\":1,"
        "\"expiry\":2}", root_hex);
    if (n <= 0 || (size_t)n >= PF_CLI_STDOUT_CAP)
        return pf_step_fail(ctx->rep, s, t0, "storage_ack input overflow");
    struct json_value doc;
    if (!pf_cli(ctx->args->bin_dir, flag, "zcode network storage_ack",
                input, &doc, error, error_cap)) {
        (void)snprintf(ctx->sr->storage_ack_status,
                       sizeof(ctx->sr->storage_ack_status),
                       "unavailable_offline");
        s->ok = true; /* recorded, not fatal */
        s->ms = now_ms() - t0;
        (void)snprintf(s->error, sizeof(s->error), "%s", error);
        return true;
    }
    const char *token = json_get_str(
        json_get(json_get(&doc, "data"), "plan_token"));
    json_free(&doc);
    bool committed = token && strlen(token) == 64 &&
                     fsj_storage_ack_commit(ctx, root_hex, flag, token,
                                            input, error, error_cap);
    (void)snprintf(ctx->sr->storage_ack_status,
                   sizeof(ctx->sr->storage_ack_status), "%s",
                   committed ? "committed" : "planned_only");
    pf_step_ok(s, t0);
    return true;
}

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
    struct fsj_ctx ctx = {
        .args = args, .store = store, .rep = rep, .tag = tag, .sr = sr,
    };
    if (!fsj_publish_plan(&ctx, release_hex, manifest_hex, recipe_hex,
                          input, error, sizeof(error))) {
        free(input);
        return false;
    }
    if (!fsj_publish_commit(&ctx, release_hex, manifest_hex, recipe_hex,
                            input, error, sizeof(error))) {
        free(input);
        return false;
    }
    struct json_value plan_doc;
    json_init(&plan_doc);
    const struct json_value *steps = NULL;
    char lock_hex[65] = {0};
    if (!fsj_add_plan(&ctx, root_hex, &plan_doc, &steps, lock_hex, error,
                      sizeof(error))) {
        free(input);
        return false;
    }
    if (!fsj_add_commit(&ctx, &plan_doc, error, sizeof(error))) {
        free(input);
        return false;
    }
    if (!fsj_second_receipt_step(&ctx, root_hex, lock_hex, steps,
                                 recipe_wire, recipe_wire_len, &plan_doc,
                                 fast, error, sizeof(error))) {
        free(input);
        return false;
    }
    if (!fsj_write_approved_verifiers(store, args->publisher_pubkey)) {
        free(input);
        return false;
    }
    if (!fsj_verify_step(&ctx, root_hex, input, error, sizeof(error))) {
        free(input);
        return false;
    }
    if (!fsj_storage_ack_step(&ctx, root_hex, input, error, sizeof(error))) {
        free(input);
        return false;
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

/* Work dir under the system temp for factory_dep_plan's confined build. */
static bool fdp_make_work_dir(char work[512])
{
    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir) tmpdir = "/tmp";
    if (snprintf(work, 512, "%s/package-factory-plan-XXXXXX", tmpdir) >= 512)
        LOG_FAIL(PF_LOG, "plan work path overflow");
    if (!mkdtemp(work))
        LOG_FAIL(PF_LOG, "mkdtemp under %s: %s", tmpdir, strerror(errno));
    return true;
}

/* Derive recipe_path/emit_dir under work, write the recipe wire there, and
 * resolve the package's absolute source path. */
static bool fdp_prepare_paths(const char *work, char *recipe_path,
                              size_t recipe_path_cap, char *emit_dir,
                              size_t emit_dir_cap, const uint8_t *recipe_wire,
                              size_t recipe_wire_len, const char *package_dir,
                              char *pkg_abs, char *error, size_t error_cap)
{
    if (snprintf(recipe_path, recipe_path_cap, "%s/recipe.wire", work) >=
            (int)recipe_path_cap ||
        snprintf(emit_dir, emit_dir_cap, "%s/emit", work) >=
            (int)emit_dir_cap)
        LOG_FAIL(PF_LOG, "plan path overflow");
    if (!pf_write_atomic(recipe_path, recipe_wire, recipe_wire_len))
        return false;
    if (!realpath(package_dir, pkg_abs)) {
        (void)snprintf(error, error_cap, "realpath %s: %s", package_dir,
                       strerror(errno));
        LOG_ERROR(PF_LOG, "%s", error);
        return false;
    }
    return true;
}

/* The locked dependency set comes from store A's add plan — the same
 * resolution the install build used. A dependency-rich plan overflows the
 * bounded reply envelope, so page through the steps array and reassemble
 * it — same contract the store journey uses. */
static bool fdp_fetch_add_plan(const struct run_args *args,
                               const char *root_hex,
                               struct json_value *plan_doc,
                               const struct json_value **steps_out,
                               char lock_hex[65], char *error,
                               size_t error_cap)
{
    if (!pf_cli_paged_steps(args->bin_dir, "zcode package add plan",
                            "name_or_root", root_hex, args->store_a,
                            plan_doc, error, error_cap))
        return false;
    const struct json_value *data = json_get(plan_doc, "data");
    const char *lk = json_get_str(json_get(data, "lock_root"));
    const struct json_value *ready = json_get(data, "ready");
    const struct json_value *steps = json_get(data, "steps");
    *steps_out = steps;
    if (!lk || strlen(lk) != 64 || !ready || !json_get_bool(ready) ||
        !steps || steps->type != JSON_ARR || !steps->num_children) {
        (void)snprintf(error, error_cap, "add plan not ready");
        return false;
    }
    (void)snprintf(lock_hex, 65, "%s", lk);
    return true;
}

/* Fixed (non-dependency) argv strings for the quick-profile plan verifier
 * spawn. */
struct fdp_verify_args {
    char bin[PF_PATH_CAP];
    char source_arg[PF_PATH_CAP + 32];
    char recipe_arg[664];
    char emit_arg[664];
    char lock_arg[96];
    char name_arg[VCS_PACKAGE_RELEASE_NAME_MAX + 32];
    char plan_arg[PF_PATH_CAP + 16];
    char fast_arg[PF_PATH_CAP + 16];
    bool use_fast;
};

static bool fdp_build_fixed_args(struct fdp_verify_args *fa,
                                 const struct run_args *args,
                                 const char *pkg_abs, const char *recipe_path,
                                 const char *emit_dir, const char *lock_hex,
                                 const char *pkg_name)
{
    if (snprintf(fa->bin, sizeof(fa->bin), "%s/zclassic23-package-verify",
                args->bin_dir) >= (int)sizeof(fa->bin))
        LOG_FAIL(PF_LOG, "verifier path overflow");
    if (!pkg_name)
        LOG_FAIL(PF_LOG, "add plan carried no target package name");
    if (snprintf(fa->source_arg, sizeof(fa->source_arg),
                "--zbuild-package-source=%s", pkg_abs) >=
                (int)sizeof(fa->source_arg) ||
        snprintf(fa->recipe_arg, sizeof(fa->recipe_arg),
                "--zbuild-package-recipe=%s", recipe_path) >=
                (int)sizeof(fa->recipe_arg) ||
        snprintf(fa->emit_arg, sizeof(fa->emit_arg), "--emit=%s", emit_dir) >=
                (int)sizeof(fa->emit_arg) ||
        snprintf(fa->lock_arg, sizeof(fa->lock_arg), "--lock-root=%s",
                lock_hex) >= (int)sizeof(fa->lock_arg) ||
        snprintf(fa->name_arg, sizeof(fa->name_arg),
                "--zbuild-package-name=%s", pkg_name) >=
                (int)sizeof(fa->name_arg))
        LOG_FAIL(PF_LOG, "verifier arg overflow");
    if (snprintf(fa->plan_arg, sizeof(fa->plan_arg), "--plan=%s",
                args->dep_plan_path) >= (int)sizeof(fa->plan_arg))
        LOG_FAIL(PF_LOG, "plan arg overflow");
    fa->use_fast = args->fast_cache_dir != NULL;
    if (fa->use_fast &&
        snprintf(fa->fast_arg, sizeof(fa->fast_arg), "--fast-cache=%s",
                args->fast_cache_dir) >= (int)sizeof(fa->fast_arg))
        LOG_FAIL(PF_LOG, "fast-cache arg overflow");
    return true;
}

/* Dep argv from the add plan's own steps (all but the last, target, step)
 * — the same resolution the install build used. */
static bool fdp_build_dep_args(const struct json_value *steps,
                               size_t step_count, const char *store_a,
                               size_t dep_stride, char **dep_args_out)
{
    size_t dep_count = step_count > 1u ? step_count - 1u : 0;
    *dep_args_out = NULL;
    if (dep_count > VCS_PACKAGE_BUILD_MAX_DEPS)
        LOG_FAIL(PF_LOG, "dep count %zu over the worker bound", dep_count);
    if (!dep_count)
        return true;
    char *dep_args = zcl_malloc(dep_stride * dep_count,
                               "factory.plan.depargs");
    if (!dep_args)
        LOG_FAIL(PF_LOG, "dep args alloc");
    for (size_t i = 0; i + 1u < step_count; i++) {
        const struct json_value *step = json_at(steps, i);
        const char *droot = json_get_str(json_get(step, "root"));
        if (!droot || strlen(droot) != 64)
            LOG_FAIL(PF_LOG, "add plan step %zu has no root", i);
        if (snprintf(dep_args + i * dep_stride, dep_stride,
                     "--dep=%s,%s/zcode/installed/%s", droot, store_a,
                     droot) >= (int)dep_stride)
            LOG_FAIL(PF_LOG, "dep arg overflow");
    }
    *dep_args_out = dep_args;
    return true;
}

/* The package name comes from the plan's target (last) step. */
static const char *fdp_resolve_pkg_name(const struct json_value *steps,
                                        size_t step_count)
{
    return json_get_str(json_get(json_at(steps, step_count - 1u), "name"));
}

/* argv: verifier <root> --zbuild-package-* profile=quick --emit
 * --lock-root [--dep=...]... --plan=<path> --require-full-isolation */
static bool fdp_run_verifier(const char *root_hex,
                             const struct fdp_verify_args *fa,
                             char *dep_args, size_t dep_count,
                             size_t dep_stride, struct pf_fast_stats *fast,
                             int *rc_out, char *error, size_t error_cap)
{
    const char *argv[14u + VCS_PACKAGE_BUILD_MAX_DEPS];
    size_t argc = 0;
    argv[argc++] = fa->bin;
    argv[argc++] = root_hex;
    argv[argc++] = fa->source_arg;
    argv[argc++] = fa->recipe_arg;
    argv[argc++] = fa->name_arg;
    argv[argc++] = "--zbuild-package-profile=quick";
    argv[argc++] = "--zbuild-package-max-cpu-seconds=120";
    argv[argc++] = fa->emit_arg;
    argv[argc++] = fa->lock_arg;
    for (size_t i = 0; i < dep_count; i++)
        argv[argc++] = dep_args + i * dep_stride;
    argv[argc++] = fa->plan_arg;
    if (fa->use_fast)
        argv[argc++] = fa->fast_arg;
    argv[argc++] = "--require-full-isolation";
    argv[argc] = NULL;
    char *vout = zcl_malloc(PF_CLI_STDOUT_CAP, "factory.plan.out");
    if (!vout)
        LOG_FAIL(PF_LOG, "verifier stdout alloc");
    *rc_out = pf_spawn((char *const *)argv, NULL, 0, vout, PF_CLI_STDOUT_CAP);
    if (fast)
        pf_fast_stats_consume(fast, vout);
    if (*rc_out != 0) {
        char *nl = strchr(vout, '\n');
        if (nl) *nl = '\0';
        (void)snprintf(error, error_cap,
                       "quick-profile plan build exit %d%s%s", *rc_out,
                       vout[0] ? ": " : "", vout);
        LOG_ERROR(PF_LOG, "%s", error);
    }
    free(vout);
    return true;
}

/* Build every verifier argv piece and spawn it. */
static bool fdp_verify_stage(const struct run_args *args,
                             const char *root_hex, const char *lock_hex,
                             const struct json_value *steps,
                             const char *pkg_abs, const char *recipe_path,
                             const char *emit_dir, int *rc_out,
                             struct pf_fast_stats *fast, char *error,
                             size_t error_cap)
{
    size_t step_count = steps->num_children;
    size_t dep_stride = PF_PATH_CAP + 96u;
    char *dep_args = NULL;
    if (!fdp_build_dep_args(steps, step_count, args->store_a, dep_stride,
                            &dep_args))
        return false;
    const char *pkg_name = fdp_resolve_pkg_name(steps, step_count);
    struct fdp_verify_args fa = {0};
    bool ok = fdp_build_fixed_args(&fa, args, pkg_abs, recipe_path, emit_dir,
                                   lock_hex, pkg_name);
    if (ok)
        ok = fdp_run_verifier(root_hex, &fa, dep_args,
                              step_count > 1u ? step_count - 1u : 0,
                              dep_stride, fast, rc_out, error, error_cap);
    free(dep_args);
    return ok;
}

/* Hash the emitted plan into the report. */
static bool fdp_hash_plan(const char *dep_plan_path, char plan_sha3_out[65],
                          char *error, size_t error_cap)
{
    uint8_t *plan = NULL;
    size_t plan_len = 0;
    if (!pf_read_file(dep_plan_path, PF_CLI_STDOUT_CAP, &plan, &plan_len)) {
        (void)snprintf(error, error_cap, "plan %s unreadable",
                       dep_plan_path);
        LOG_ERROR(PF_LOG, "%s", error);
        return false;
    }
    uint8_t digest[32];
    sha3_256(plan, plan_len, digest);
    free(plan);
    zcl_hex_encode(digest, 32, plan_sha3_out);
    return true;
}

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
    if (!fdp_make_work_dir(work))
        return false;
    char recipe_path[600], emit_dir[600], pkg_abs[PF_PATH_CAP];
    bool ok = fdp_prepare_paths(work, recipe_path, sizeof(recipe_path),
                                emit_dir, sizeof(emit_dir), recipe_wire,
                                recipe_wire_len, args->package_dir, pkg_abs,
                                error, error_cap);
    char lock_hex[65] = {0};
    struct json_value plan_doc;
    json_init(&plan_doc);
    const struct json_value *steps = NULL;
    if (ok)
        ok = fdp_fetch_add_plan(args, root_hex, &plan_doc, &steps, lock_hex,
                                error, error_cap);
    int rc = -1;
    if (ok)
        ok = fdp_verify_stage(args, root_hex, lock_hex, steps, pkg_abs,
                              recipe_path, emit_dir, &rc, fast, error,
                              error_cap);
    json_free(&plan_doc);
    if (ok && rc != 0) ok = false;
    if (ok)
        ok = fdp_hash_plan(args->dep_plan_path, plan_sha3_out, error,
                           error_cap);
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

static uint16_t fa_resolve_kind(const struct run_args *args)
{
    if (strcmp(args->kind, "human") == 0)
        return VCS_ZCODE_SOURCE_HUMAN_AUTHORED;
    if (strcmp(args->kind, "import") == 0)
        return VCS_ZCODE_SOURCE_CANONICAL_IMPORT;
    return VCS_ZCODE_SOURCE_AI_AUTHORED;
}

/* author binding: publisher pubkey hex; assignment evidence: the release
 * id (the factory has no scopes.def line). */
static bool fa_author_evidence_roots(const struct run_args *args,
                                     const uint8_t release_id[32],
                                     uint8_t author_root[32],
                                     uint8_t evidence_root_a[32])
{
    return vcs_signed_evidence_root(k_domain_author, sizeof(k_domain_author),
                                    (const uint8_t *)args->publisher_pubkey,
                                    strlen(args->publisher_pubkey),
                                    author_root) &&
           vcs_signed_evidence_root(k_domain_assignment_evidence,
                                    sizeof(k_domain_assignment_evidence),
                                    release_id, 32, evidence_root_a);
}

/* license: the census license wire over the package LICENSE. */
static bool fa_license_root(const char *package_dir, uint8_t license_root[32],
                            char *error, size_t error_cap)
{
    size_t plen = strlen(package_dir) + sizeof("/LICENSE");
    char *lpath = zcl_malloc(plen, "factory.license");
    if (!lpath)
        LOG_FAIL(PF_LOG, "license path alloc");
    (void)snprintf(lpath, plen, "%s/LICENSE", package_dir);
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
         vcs_signed_evidence_root(k_domain_license, sizeof(k_domain_license),
                                  wire.p, wire.len, license_root);
    buf_free(&wire);
    free(lbytes);
    if (!ok)
        LOG_FAIL(PF_LOG, "license root failed");
    return true;
}

static bool fa_build_assignment(const struct run_args *args,
                                const struct vcs_package_prepared *prepared,
                                uint16_t kind, const uint8_t author_root[32],
                                const uint8_t license_root[32],
                                const uint8_t evidence_root_a[32],
                                const uint8_t seed[32],
                                uint8_t assignment_root[32])
{
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
    cerr = vcs_zcode_source_assignment_v1_root(&assignment, assignment_root);
    if (cerr != VCS_ZCODE_C23_OK)
        LOG_FAIL(PF_LOG, "assignment root: %s",
                 vcs_zcode_c23_error_string(cerr));
    memory_cleanse(&assignment, sizeof(assignment));
    return true;
}

/* dependency closure root: name || NUL || root || NUL || semver || NUL per
 * zcode-package.json dependency (file order), the census recipe. */
static bool fa_dep_closure_root(const struct gate_info *info,
                                uint8_t dep_closure_root[32])
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
                                      sizeof(k_domain_dep_closure), cwire.p,
                                      cwire.len, dep_closure_root);
    buf_free(&cwire);
    if (!ok)
        LOG_FAIL(PF_LOG, "dependency closure root failed");
    return true;
}

static bool fa_check_family_policy(uint8_t family_policy_root[32])
{
    struct vcs_zcode_family_policy_v1 policy;
    vcs_zcode_family_policy_v1_default(&policy);
    uint8_t frozen[32];
    if (vcs_zcode_family_policy_v1_root(&policy, family_policy_root) !=
            VCS_ZCODE_COMMONS_OK ||
        !zcl_hex_decode_lower(PF_FAMILY_POLICY_ROOT_HEX, frozen, 32) ||
        memcmp(family_policy_root, frozen, 32) != 0)
        LOG_FAIL(PF_LOG, "family policy root mismatch with the frozen "
                 "constant");
    return true;
}

static bool fa_admission_evidence_roots(const uint8_t assignment_root[32],
                                        uint8_t moderation_root[32],
                                        uint8_t panel_root[32],
                                        uint8_t adm_evidence[32])
{
    return vcs_signed_evidence_root(k_domain_moderation,
                                    sizeof(k_domain_moderation), NULL, 0,
                                    moderation_root) &&
           vcs_signed_evidence_root(k_domain_panel, sizeof(k_domain_panel),
                                    (const uint8_t *)k_panel_literal,
                                    strlen(k_panel_literal), panel_root) &&
           vcs_signed_evidence_root(k_domain_admission_evidence,
                                    sizeof(k_domain_admission_evidence),
                                    assignment_root, 32, adm_evidence);
}

/* Founding self-screen: tier 0 with the SELF_SCREENED state; zero
 * independent operator groups (disclosed in the report). */
static bool fa_build_admission(
    const struct run_args *args, const struct vcs_package_prepared *prepared,
    const uint8_t dep_closure_root[32], const uint8_t family_policy_root[32],
    const uint8_t moderation_root[32], const uint8_t panel_root[32],
    const uint8_t adm_evidence[32], const uint8_t seed[32],
    uint8_t admission_root_out[32],
    struct vcs_zcode_commons_admission_v1 *admission)
{
    memset(admission, 0, sizeof(*admission));
    admission->schema_version = 1;
    admission->flags = VCS_ZCODE_COMMONS_REQUIRED_FLAGS;
    admission->state = VCS_ZCODE_ADMISSION_SELF_SCREENED;
    admission->tier = VCS_ZCODE_MODERATION_TIER_SELF_SCREENED;
    admission->coverage_complete = 1;
    admission->closure_complete = 1;
    admission->sequence = 1;
    admission->decided_height = args->cutoff_height;
    admission->decided_mtp = args->cutoff_mtp;
    admission->expires_height =
        args->cutoff_height + PF_ADMISSION_EXPIRY_BLOCKS;
    admission->expires_mtp =
        args->cutoff_mtp + PF_ADMISSION_EXPIRY_MTP_SECONDS;
    memcpy(admission->content_root, prepared->package_root, 32);
    memcpy(admission->dependency_closure_root, dep_closure_root, 32);
    memcpy(admission->family_policy_root, family_policy_root, 32);
    memcpy(admission->moderation_set_root, moderation_root, 32);
    memcpy(admission->panel_root, panel_root, 32);
    memcpy(admission->evidence_root, adm_evidence, 32);
    enum vcs_zcode_family_admission_error aerr =
        vcs_zcode_commons_admission_v1_sign(admission, seed);
    if (aerr != VCS_ZCODE_FAMILY_ADMISSION_OK)
        LOG_FAIL(PF_LOG, "admission sign: %s",
                 vcs_zcode_family_admission_error_string(aerr));
    aerr = vcs_zcode_commons_admission_v1_root(admission, admission_root_out);
    if (aerr != VCS_ZCODE_FAMILY_ADMISSION_OK)
        LOG_FAIL(PF_LOG, "admission root: %s",
                 vcs_zcode_family_admission_error_string(aerr));
    return true;
}

static bool fa_encode_admission(
    struct vcs_zcode_commons_admission_v1 *admission,
    uint8_t **admission_wire_out, size_t *admission_wire_len_out)
{
    size_t wire_cap = VCS_ZCODE_COMMONS_ADMISSION_WIRE_BYTES;
    uint8_t *wire = zcl_malloc(wire_cap, "factory.admission");
    if (!wire)
        LOG_FAIL(PF_LOG, "admission wire alloc");
    enum vcs_zcode_family_admission_error aerr =
        vcs_zcode_commons_admission_v1_encode(admission, wire, wire_cap,
                                              admission_wire_len_out);
    memory_cleanse(admission, sizeof(*admission));
    if (aerr != VCS_ZCODE_FAMILY_ADMISSION_OK) {
        free(wire);
        LOG_FAIL(PF_LOG, "admission encode: %s",
                 vcs_zcode_family_admission_error_string(aerr));
    }
    *admission_wire_out = wire;
    return true;
}

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
    uint16_t kind = fa_resolve_kind(args);
    uint8_t author_root[32], evidence_root_a[32], license_root[32];
    if (!fa_author_evidence_roots(args, release_id, author_root,
                                  evidence_root_a))
        LOG_FAIL(PF_LOG, "admission sub-roots failed");
    if (!fa_license_root(args->package_dir, license_root, error, error_cap))
        return false;
    uint8_t assignment_root[32];
    if (!fa_build_assignment(args, prepared, kind, author_root, license_root,
                             evidence_root_a, seed, assignment_root))
        return false;
    uint8_t dep_closure_root[32];
    if (!fa_dep_closure_root(info, dep_closure_root))
        return false;
    uint8_t family_policy_root[32];
    if (!fa_check_family_policy(family_policy_root))
        return false;
    uint8_t moderation_root[32], panel_root[32], adm_evidence[32];
    if (!fa_admission_evidence_roots(assignment_root, moderation_root,
                                     panel_root, adm_evidence))
        LOG_FAIL(PF_LOG, "admission sub-roots failed");
    struct vcs_zcode_commons_admission_v1 admission;
    if (!fa_build_admission(args, prepared, dep_closure_root,
                            family_policy_root, moderation_root, panel_root,
                            adm_evidence, seed, admission_root_out,
                            &admission))
        return false;
    if (!fa_encode_admission(&admission, admission_wire_out,
                             admission_wire_len_out))
        return false;
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
static bool frc_read_existing(const char *def_path, uint8_t **text,
                              size_t *len, char *error, size_t error_cap)
{
    bool exists = access(def_path, R_OK) == 0;
    if (exists && !pf_read_file(def_path, 1024u * 1024u, text, len)) {
        (void)snprintf(error, error_cap, "cannot read %s", def_path);
        return false;
    }
    return true;
}

static char *frc_build_line(const char *name, const char *root_hex,
                            const char *store_label, const char *kind,
                            const char *spdx)
{
    size_t line_cap = strlen(name) + strlen(root_hex) + strlen(store_label) +
                      strlen(kind) + strlen(spdx) + 64u;
    char *line = zcl_malloc(line_cap, "factory.defline");
    if (!line)
        LOG_NULL(PF_LOG, "def line alloc");
    (void)snprintf(line, line_cap, "package %s | root %s | store %s | "
                   "kind %s | spdx %s", name, root_hex, store_label, kind,
                   spdx);
    return line;
}

/* Replace the existing "package NAME | ..." line if one exists (fails on a
 * duplicate); otherwise every input line is copied through unchanged and
 * the caller appends the new line. */
static bool frc_rewrite_lines(const uint8_t *text, size_t len,
                              const char *name, const char *def_path,
                              const char *line, struct buf *out,
                              bool *replaced, char *error, size_t error_cap)
{
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
            if (*replaced) {
                (void)snprintf(error, error_cap,
                               "duplicate package line for %s in %s", name,
                               def_path);
                LOG_ERROR(PF_LOG, "%s", error);
                ok = false;
                break;
            }
            ok = buf_put(out, line, strlen(line));
            *replaced = true;
        } else {
            ok = buf_put(out, text + pos, eol - pos);
        }
        if (ok && eol < len) ok = buf_put(out, "\n", 1);
        pos = eol + 1u;
    }
    return ok;
}

static bool frc_append_line(const uint8_t *text, size_t len,
                            const char *line, struct buf *out)
{
    bool ok = true;
    if (len && text[len - 1] != '\n') ok = buf_put(out, "\n", 1);
    if (ok)
        ok = buf_put(out, line, strlen(line)) && buf_put(out, "\n", 1);
    return ok;
}

static bool factory_register_corpus(const char *def_path, const char *name,
                                    const char *root_hex, const char *store_a,
                                    const char *kind, const char *spdx,
                                    char *error, size_t error_cap)
{
    uint8_t *text = NULL;
    size_t len = 0;
    if (!frc_read_existing(def_path, &text, &len, error, error_cap))
        return false;
    char store_label[PF_PATH_CAP];
    if (!pf_store_label(store_a, store_label, sizeof(store_label), error,
                        error_cap)) {
        free(text);
        return false;
    }
    char *line = frc_build_line(name, root_hex, store_label, kind, spdx);
    if (!line) {
        free(text);
        return false;
    }
    struct buf out = {0};
    bool replaced = false;
    bool ok = frc_rewrite_lines(text, len, name, def_path, line, &out,
                                &replaced, error, error_cap);
    if (ok && !replaced)
        ok = frc_append_line(text, len, line, &out);
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

/* Shared mutable state threaded through cmd_run's numbered steps. */
struct cmd_run_state {
    struct pf_report rep;
    char error[PF_ERROR_CAP];
    struct gate_info info;
    struct vcs_package_prepared prepared;
    bool prepared_ok;
    char release_hex[VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES * 2u + 1u];
    char release_id_hex[65];
    char root_hex[65];
    char recipe_root_hex[65];
    uint8_t release_id[32];
    char signature_hex[129];
    uint8_t *release_wire;
    size_t release_wire_len;
    uint8_t admission_root[32];
    uint8_t *admission_wire;
    size_t admission_wire_len;
    struct store_result sa, sb;
    struct pf_fast_stats fast_stats;
    char dep_plan_sha3[65];
    bool corpus_registered;
    char corpus_note[320];
    uint64_t t_start;
};

/* 1. GATE */
static void cr_step_gate(const struct run_args *args,
                         struct cmd_run_state *st)
{
    struct pf_step *s = pf_step_begin(&st->rep, "gate");
    uint64_t t0 = now_ms();
    if (gate_check(args->package_dir, &st->info, st->error,
                   sizeof(st->error)))
        pf_step_ok(s, t0);
    else
        (void)pf_step_fail(&st->rep, s, t0, st->error);
}

/* 2. prepare */
static void cr_step_prepare(const struct run_args *args,
                            struct cmd_run_state *st)
{
    struct pf_step *s = pf_step_begin(&st->rep, "prepare");
    uint64_t t0 = now_ms();
    if (st->rep.failed)
        return;
    uint8_t pubkey[33];
    if (strlen(args->publisher_pubkey) != 66 ||
        !zcl_hex_decode_lower(args->publisher_pubkey, pubkey, 33)) {
        (void)snprintf(st->error, sizeof(st->error),
                       "publisher pubkey must be 66 lowercase hex");
        (void)pf_step_fail(&st->rep, s, t0, st->error);
        return;
    }
    struct vcs_package_prepare_options options = {
        .dir = args->package_dir,
        .reward_address = NULL,
        .chain_id = args->chain_id,
    };
    memcpy(options.publisher_pubkey, pubkey, 33);
    options.publisher_sequence = args->publisher_sequence;
    char detail[256] = {0};
    enum vcs_package_prepare_error perr = vcs_package_prepare(
        &options, &st->prepared, detail, sizeof(detail));
    if (perr != VCS_PACKAGE_PREPARE_OK) {
        (void)snprintf(st->error, sizeof(st->error), "%s: %s",
                       vcs_package_prepare_error_string(perr), detail);
        (void)pf_step_fail(&st->rep, s, t0, st->error);
        return;
    }
    if (strcmp(st->prepared.release.name, st->info.name) != 0 ||
        strcmp(st->prepared.release.license, st->info.license) != 0) {
        (void)snprintf(st->error, sizeof(st->error),
                       "prepare/metadata name or license mismatch");
        (void)pf_step_fail(&st->rep, s, t0, st->error);
        vcs_package_prepared_free(&st->prepared);
        return;
    }
    st->prepared_ok = true;
    pf_root_hex(st->prepared.package_root, st->root_hex);
    pf_root_hex(st->prepared.recipe_root, st->recipe_root_hex);
    pf_step_ok(s, t0);
}

/* 3. key cross-check + sign the digest offline */
static void cr_step_sign(const struct run_args *args,
                         struct cmd_run_state *st)
{
    struct pf_step *s = pf_step_begin(&st->rep, "sign");
    uint64_t t0 = now_ms();
    if (st->rep.failed || !st->prepared_ok)
        return;
    char key_pub[256];
    if (!pf_signer(args->bin_dir, "--public", NULL, args->key_file, key_pub,
                   sizeof(key_pub), st->error, sizeof(st->error))) {
        (void)pf_step_fail(&st->rep, s, t0, st->error);
        return;
    }
    if (strcmp(key_pub, args->publisher_pubkey) != 0) {
        (void)pf_step_fail(&st->rep, s, t0,
                           "publisher-key-file does not match "
                           "--publisher-pubkey");
        return;
    }
    char digest_hex[65];
    pf_root_hex(st->prepared.signing_digest, digest_hex);
    if (!pf_signer(args->bin_dir, "--sign-digest", digest_hex,
                   args->key_file, st->signature_hex,
                   sizeof(st->signature_hex), st->error, sizeof(st->error))) {
        (void)pf_step_fail(&st->rep, s, t0, st->error);
        return;
    }
    if (strlen(st->signature_hex) != 128) {
        (void)pf_step_fail(&st->rep, s, t0, "bad signature hex");
        return;
    }
    pf_step_ok(s, t0);
}

/* In-process verification: parse the release wire, verify it, take its id,
 * re-serialize it, and require the canonical bytes to match what was just
 * assembled. */
static bool cr_seal_verify(const uint8_t *release_wire,
                           size_t release_wire_len, uint8_t release_id[32],
                           char *error, size_t error_cap)
{
    struct vcs_package_release rel;
    enum vcs_package_release_error rerr =
        vcs_package_release_parse(release_wire, release_wire_len, &rel);
    if (rerr == VCS_PACKAGE_RELEASE_OK)
        rerr = vcs_package_release_verify(&rel);
    uint8_t *canon = NULL;
    size_t canon_len = 0;
    if (rerr == VCS_PACKAGE_RELEASE_OK)
        rerr = vcs_package_release_id(&rel, release_id);
    if (rerr == VCS_PACKAGE_RELEASE_OK)
        rerr = vcs_package_release_serialize(&rel, &canon, &canon_len);
    if (rerr != VCS_PACKAGE_RELEASE_OK || canon_len != release_wire_len ||
        memcmp(canon, release_wire, release_wire_len) != 0) {
        (void)snprintf(error, error_cap, "release verification: %s",
                       vcs_package_release_error_string(rerr));
        free(canon);
        return false;
    }
    free(canon);
    return true;
}

/* 4. seal (in-process verification + canonical re-serialization) */
static void cr_step_seal(const struct run_args *args,
                         struct cmd_run_state *st)
{
    (void)args;
    struct pf_step *s = pf_step_begin(&st->rep, "seal");
    uint64_t t0 = now_ms();
    if (st->rep.failed || !st->prepared_ok || !st->signature_hex[0])
        return;
    uint8_t signature[64];
    bool ok = zcl_hex_decode_lower(st->signature_hex, signature, 64);
    size_t body_plus = st->prepared.release_body_len + 64u;
    st->release_wire = ok ? zcl_malloc(body_plus, "factory.release") : NULL;
    if (!st->release_wire) {
        (void)pf_step_fail(&st->rep, s, t0, "release wire alloc/decode");
        return;
    }
    memcpy(st->release_wire, st->prepared.release_body,
           st->prepared.release_body_len);
    memcpy(st->release_wire + st->prepared.release_body_len, signature, 64);
    st->release_wire_len = body_plus;
    if (!cr_seal_verify(st->release_wire, st->release_wire_len,
                        st->release_id, st->error, sizeof(st->error))) {
        (void)pf_step_fail(&st->rep, s, t0, st->error);
        return;
    }
    hex_take(st->release_hex, sizeof(st->release_hex), st->release_wire,
             st->release_wire_len);
    pf_root_hex(st->release_id, st->release_id_hex);
    pf_step_ok(s, t0);
}

/* 5./6. store A then store B, identical wires */
static bool cr_step_stores(const struct run_args *args,
                           struct cmd_run_state *st)
{
    if (st->rep.failed || !st->prepared_ok || !st->release_wire)
        return true;
    char *manifest_hex = zcl_malloc(st->prepared.manifest_wire_len * 2u + 1u,
                                    "factory.manifest.hex");
    char *recipe_hex_s = zcl_malloc(st->prepared.recipe_wire_len * 2u + 1u,
                                    "factory.recipe.hex");
    if (!manifest_hex || !recipe_hex_s) {
        LOG_ERROR(PF_LOG, "hex alloc");
        free(manifest_hex);
        free(recipe_hex_s);
        return false;
    }
    hex_take(manifest_hex, st->prepared.manifest_wire_len * 2u + 1u,
             st->prepared.manifest_wire, st->prepared.manifest_wire_len);
    hex_take(recipe_hex_s, st->prepared.recipe_wire_len * 2u + 1u,
             st->prepared.recipe_wire, st->prepared.recipe_wire_len);
    bool ok_a = factory_store_journey(
        args, args->store_a, st->release_hex, manifest_hex, recipe_hex_s,
        st->prepared.recipe_wire, st->prepared.recipe_wire_len, st->root_hex,
        &st->rep, "a", &st->sa, &st->fast_stats);
    bool ok_b = ok_a &&
        factory_store_journey(args, args->store_b, st->release_hex,
                              manifest_hex, recipe_hex_s,
                              st->prepared.recipe_wire,
                              st->prepared.recipe_wire_len, st->root_hex,
                              &st->rep, "b", &st->sb, &st->fast_stats);
    (void)ok_b;
    free(manifest_hex);
    free(recipe_hex_s);
    return true;
}

/* 7. exact dependency plan (zcl.dep_plan.v1; local evidence only) */
static void cr_step_dep_plan(const struct run_args *args,
                             struct cmd_run_state *st)
{
    if (st->rep.failed || !st->prepared_ok || !args->dep_plan_path)
        return;
    struct pf_step *s = pf_step_begin(&st->rep, "dep_plan");
    uint64_t t0 = now_ms();
    if (factory_dep_plan(args, st->root_hex, st->prepared.recipe_wire,
                         st->prepared.recipe_wire_len, st->dep_plan_sha3,
                         &st->fast_stats, st->error, sizeof(st->error)))
        pf_step_ok(s, t0);
    else
        (void)pf_step_fail(&st->rep, s, t0, st->error);
}

/* Resolve the signer seed path (--signer-seed-file, else
 * $HOME/.config/zclassic23/corpus-census-signer.seed) and load/create it. */
static bool cr_admission_load_seed(const struct run_args *args,
                                   uint8_t seed[32], char *error,
                                   size_t error_cap)
{
    char default_seed[PF_PATH_CAP];
    const char *seed_path = args->signer_seed_file;
    if (!seed_path) {
        const char *home = getenv("HOME");
        if (!home ||
            snprintf(default_seed, sizeof(default_seed),
                     "%s/.config/zclassic23/corpus-census-signer.seed",
                     home) >= (int)sizeof(default_seed)) {
            (void)snprintf(error, error_cap,
                           "HOME unset; pass --signer-seed-file");
            return false;
        }
        seed_path = default_seed;
    }
    if (!pf_seed_load_or_create(seed_path, seed)) {
        (void)snprintf(error, error_cap, "signer seed load/create");
        return false;
    }
    return true;
}

/* 8. self-screened admission (census construction) */
static void cr_step_admission(const struct run_args *args,
                              struct cmd_run_state *st)
{
    struct pf_step *s = pf_step_begin(&st->rep, "admission");
    uint64_t t0 = now_ms();
    if (st->rep.failed)
        return;
    uint8_t seed[32];
    if (!cr_admission_load_seed(args, seed, st->error, sizeof(st->error))) {
        (void)pf_step_fail(&st->rep, s, t0, st->error);
        return;
    }
    bool ok = factory_admission(args, &st->info, &st->prepared,
                                st->release_id, seed, st->admission_root,
                                &st->admission_wire, &st->admission_wire_len,
                                st->error, sizeof(st->error));
    memory_cleanse(seed, sizeof(seed));
    if (!ok)
        (void)pf_step_fail(&st->rep, s, t0,
                           st->error[0] ? st->error : "admission failed");
    else
        pf_step_ok(s, t0);
}

/* 9. corpus registration */
static void cr_step_corpus(const struct run_args *args,
                           struct cmd_run_state *st)
{
    if (st->rep.failed || !args->register_corpus)
        return;
    struct pf_step *s = pf_step_begin(&st->rep, "register_corpus");
    uint64_t t0 = now_ms();
    st->error[0] = '\0';
    if (factory_register_corpus(args->census_def, st->info.name,
                                st->root_hex, args->store_a, args->kind,
                                st->info.license, st->error,
                                sizeof(st->error))) {
        st->corpus_registered = true;
        (void)snprintf(st->corpus_note, sizeof(st->corpus_note),
            "rerun: make corpus-census CORPUS_OUT=corpus "
            "CORPUS_SEQUENCE=<n> CORPUS_PREDECESSOR_ROOT=<root> "
            "CORPUS_CUTOFF_HEIGHT=<h> CORPUS_CUTOFF_MTP=<m> "
            "CORPUS_QUALITY_ATTESTED=<0|1>");
        pf_step_ok(s, t0);
    } else {
        (void)pf_step_fail(&st->rep, s, t0, st->error);
    }
}

/* 10. report — "package" section. */
static void cr_report_package(struct json_value *report,
                              const struct run_args *args,
                              const struct cmd_run_state *st)
{
    struct json_value pkg;
    json_init(&pkg);
    json_set_object(&pkg);
    (void)json_push_kv_str(&pkg, "dir", args->package_dir);
    (void)json_push_kv_str(&pkg, "name", st->info.name);
    (void)json_push_kv_str(&pkg, "semver", st->info.semver);
    (void)json_push_kv_str(&pkg, "license", st->info.license);
    (void)json_push_kv_str(&pkg, "package_root", st->root_hex);
    (void)json_push_kv_str(&pkg, "recipe_root", st->recipe_root_hex);
    (void)json_push_kv_str(&pkg, "release_id", st->release_id_hex);
    (void)json_push_kv_str(&pkg, "publisher_pubkey", args->publisher_pubkey);
    (void)json_push_kv_int(&pkg, "publisher_sequence",
                           (int64_t)args->publisher_sequence);
    (void)json_push_kv_str(&pkg, "kind", args->kind);
    (void)json_push_kv(report, "package", &pkg);
    json_free(&pkg);
}

/* One row ("a" or "b") of the report's "stores" section. */
static void cr_report_store_row(struct json_value *stores, const char *key,
                                const char *dir,
                                const struct store_result *sr)
{
    struct json_value so;
    json_init(&so);
    json_set_object(&so);
    /* The store LABEL, not the datadir. This report is a tracked file
     * under corpus/factory/; an absolute datadir here published the
     * operator's home directory in every one of them. The label is the
     * store's identity — where it lives is operator-local and is supplied
     * at run time by --store-a/--store-b. */
    {
        char label[PF_PATH_CAP];
        char lerr[PF_ERROR_CAP] = {0};
        (void)json_push_kv_str(&so, "store",
            pf_store_label(dir, label, sizeof(label), lerr, sizeof(lerr))
                ? label : "unnamed");
    }
    (void)json_push_kv_bool(&so, "published", sr->publish_ok);
    (void)json_push_kv_bool(&so, "installed", sr->add_ok);
    (void)json_push_kv_str(&so, "plan_id", sr->plan_id);
    (void)json_push_kv_str(&so, "receipt_quick", sr->receipt_quick);
    (void)json_push_kv_str(&so, "receipt_standard", sr->receipt_standard);
    (void)json_push_kv_bool(&so, "reproduced", sr->reproduced);
    (void)json_push_kv_str(&so, "storage_ack",
        sr->storage_ack_status[0] ? sr->storage_ack_status
                                  : "not_attempted");
    (void)json_push_kv(stores, key, &so);
    json_free(&so);
}

/* 10. report — "stores" section. */
static void cr_report_stores(struct json_value *report,
                             const struct run_args *args,
                             const struct cmd_run_state *st)
{
    struct json_value stores;
    json_init(&stores);
    json_set_object(&stores);
    cr_report_store_row(&stores, "a", args->store_a, &st->sa);
    cr_report_store_row(&stores, "b", args->store_b, &st->sb);
    (void)json_push_kv(report, "stores", &stores);
    json_free(&stores);
}

/* 10. report — "admission" section. */
static bool cr_report_admission(struct json_value *report,
                                const struct cmd_run_state *st)
{
    char ahex[65];
    pf_root_hex(st->admission_root, ahex);
    struct json_value adm;
    json_init(&adm);
    json_set_object(&adm);
    (void)json_push_kv_str(&adm, "admission_root",
        zcl_bytes_any_set(st->admission_root, 32) ? ahex : "");
    if (st->admission_wire) {
        size_t hex_len = st->admission_wire_len * 2u;
        char *hex = zcl_malloc(hex_len + 1u, "factory.adm.hex");
        if (!hex) {
            LOG_ERROR(PF_LOG, "admission hex alloc");
            json_free(&adm);
            return false;
        }
        zcl_hex_encode(st->admission_wire, st->admission_wire_len, hex);
        (void)json_push_kv_str(&adm, "admission_wire", hex);
        free(hex);
    }
    (void)json_push_kv_str(&adm, "screen", "self-screened");
    (void)json_push_kv(report, "admission", &adm);
    json_free(&adm);
    return true;
}

/* 10. report — "dep_plan" section (only when a plan path was requested). */
static void cr_report_dep_plan(struct json_value *report,
                               const struct run_args *args,
                               const struct cmd_run_state *st)
{
    if (!args->dep_plan_path)
        return;
    struct json_value dp;
    json_init(&dp);
    json_set_object(&dp);
    (void)json_push_kv_str(&dp, "schema", "zcl.dep_plan.v1");
    (void)json_push_kv_str(&dp, "path", args->dep_plan_path);
    (void)json_push_kv_str(&dp, "sha3", st->dep_plan_sha3);
    (void)json_push_kv(report, "dep_plan", &dp);
    json_free(&dp);
}

/* 10. report — "fast_cache" section (only when a fast-cache dir was
 * configured). */
static void cr_report_fast_cache(struct json_value *report,
                                 const struct run_args *args,
                                 const struct cmd_run_state *st)
{
    if (!args->fast_cache_dir)
        return;
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
            pf_store_label(args->fast_cache_dir, label, sizeof(label), lerr,
                           sizeof(lerr)) ? label : "unnamed");
    }
    (void)json_push_kv_int(&fc, "hits", (int64_t)st->fast_stats.hits);
    (void)json_push_kv_int(&fc, "misses", (int64_t)st->fast_stats.misses);
    (void)json_push_kv_int(&fc, "objects_reused_bytes",
                           (int64_t)st->fast_stats.reused_bytes);
    (void)json_push_kv_str(&fc, "admission", "local_candidate");
    (void)json_push_kv_str(&fc, "note",
        "quarantined local candidate cache; cached objects speed up only "
        "this node's confined rebuilds and are never attestation or "
        "admission evidence");
    (void)json_push_kv_str(&fc, "applies_to",
        "package-verify --zbuild-package-* rebuilds (second receipt and "
        "dep plan steps)");
    (void)json_push_kv(report, "fast_cache", &fc);
    json_free(&fc);
}

/* 10. report — "steps" section. */
static void cr_report_steps(struct json_value *report,
                            const struct cmd_run_state *st)
{
    struct json_value steps;
    json_init(&steps);
    json_set_array(&steps);
    for (size_t i = 0; i < st->rep.step_count; i++) {
        struct json_value so;
        json_init(&so);
        json_set_object(&so);
        (void)json_push_kv_str(&so, "name", st->rep.steps[i].name);
        (void)json_push_kv_bool(&so, "ok", st->rep.steps[i].ok);
        (void)json_push_kv_int(&so, "ms", (int64_t)st->rep.steps[i].ms);
        if (st->rep.steps[i].error[0])
            (void)json_push_kv_str(&so, "error", st->rep.steps[i].error);
        (void)json_push_back(&steps, &so);
        json_free(&so);
    }
    (void)json_push_kv(report, "steps", &steps);
    json_free(&steps);
}

/* 10. report — "disclosures" section. */
static void cr_report_disclosures(struct json_value *report)
{
    struct json_value disc;
    json_init(&disc);
    json_set_array(&disc);
    struct json_value v;
#define PF_DISCLOSE(text)                        \
    json_init(&v);                               \
    json_set_str(&v, text);                      \
    (void)json_push_back(&disc, &v);             \
    json_free(&v)
    PF_DISCLOSE("same-host reproduction: both confined builds ran on one "
                "host with one toolchain (quick + standard flag profiles); "
                "independent-operator reproduction is future work");
    PF_DISCLOSE("self-screen admission: the commons_admission.v1 is "
                "self-signed SELF_SCREENED (tier 0); zero independent "
                "operator groups participated");
    PF_DISCLOSE("offline run: no network durability — storage_ack needs "
                "the live DHT service; durable_hosting is "
                "unavailable_offline unless a store reports otherwise");
    PF_DISCLOSE("the approved_verifiers allowlist in each store was "
                "created by the factory with the publisher key so the "
                "verify command could run; no verifier quorum was reached "
                "and none is claimed");
#undef PF_DISCLOSE
    (void)json_push_kv(report, "disclosures", &disc);
    json_free(&disc);
}

static const char *cr_durable_hosting(const struct cmd_run_state *st)
{
    return (st->sa.storage_ack_status[0] &&
            strcmp(st->sa.storage_ack_status, "unavailable_offline") != 0) ||
           (st->sb.storage_ack_status[0] &&
            strcmp(st->sb.storage_ack_status, "unavailable_offline") != 0)
        ? "attempted"
        : "unavailable_offline";
}

static bool cr_write_report_file(const struct run_args *args,
                                 struct json_value *report)
{
    size_t need = json_write(report, NULL, 0);
    char *text = zcl_malloc(need + 2u, "factory.report.out");
    if (!text) {
        LOG_ERROR(PF_LOG, "report buffer alloc");
        return false;
    }
    size_t written = json_write(report, text, need + 1u);
    if (written > need) {
        LOG_ERROR(PF_LOG, "report write overflow");
        free(text);
        return false;
    }
    text[written] = '\n';
    if (!pf_write_atomic(args->report_path, (const uint8_t *)text,
                         written + 1u)) {
        free(text);
        LOG_ERROR(PF_LOG, "cannot write report %s", args->report_path);
        return false;
    }
    free(text);
    return true;
}

/* 10. report */
static bool cr_step_report(const struct run_args *args,
                           struct cmd_run_state *st)
{
    uint64_t total_ms = now_ms() - st->t_start;
    struct json_value report;
    json_init(&report);
    json_set_object(&report);
    (void)json_push_kv_str(&report, "schema",
                           "zcl.package_factory.report.v1");
    (void)json_push_kv_bool(&report, "ok", !st->rep.failed);
    (void)json_push_kv_int(&report, "total_ms", (int64_t)total_ms);
    cr_report_package(&report, args, st);
    cr_report_stores(&report, args, st);
    bool ok = cr_report_admission(&report, st);
    cr_report_dep_plan(&report, args, st);
    cr_report_fast_cache(&report, args, st);
    cr_report_steps(&report, st);
    cr_report_disclosures(&report);
    (void)json_push_kv_str(&report, "durable_hosting",
                           cr_durable_hosting(st));
    (void)json_push_kv_bool(&report, "corpus_registered",
                            st->corpus_registered);
    if (st->corpus_note[0])
        (void)json_push_kv_str(&report, "corpus_next_step", st->corpus_note);
    if (ok)
        ok = cr_write_report_file(args, &report);
    json_free(&report);
    return ok;
}

static void cr_print_summary(const struct run_args *args,
                             const struct cmd_run_state *st)
{
    printf("package-factory: %s package=%s root=%s release=%s\n",
           st->rep.failed ? "FAILED" : "ok", st->info.name, st->root_hex,
           st->release_id_hex);
    printf("  reproduced: storeA=%d storeB=%d  durable_hosting=%s\n",
           (int)st->sa.reproduced, (int)st->sb.reproduced,
           (st->sa.storage_ack_status[0] &&
            strcmp(st->sa.storage_ack_status, "unavailable_offline") != 0)
               ? st->sa.storage_ack_status
               : "unavailable_offline");
    if (st->corpus_registered)
        printf("  corpus: registered in %s — %s\n", args->census_def,
               st->corpus_note);
    printf("  report: %s\n", args->report_path);
}

static void cr_cleanup(struct cmd_run_state *st)
{
    for (size_t i = 0; i < st->rep.step_count; i++)
        free((void *)st->rep.steps[i].name);
    free(st->release_wire);
    free(st->admission_wire);
    if (st->prepared_ok) vcs_package_prepared_free(&st->prepared);
    gate_info_free(&st->info);
}

static int cmd_run(const struct run_args *args)
{
    struct cmd_run_state st;
    memset(&st, 0, sizeof(st));
    st.t_start = now_ms();

    cr_step_gate(args, &st);
    cr_step_prepare(args, &st);
    cr_step_sign(args, &st);
    cr_step_seal(args, &st);
    if (!cr_step_stores(args, &st))
        return -1;
    cr_step_dep_plan(args, &st);
    cr_step_admission(args, &st);
    cr_step_corpus(args, &st);
    if (!cr_step_report(args, &st))
        return -1;
    cr_print_summary(args, &st);
    int rc = st.rep.failed ? 1 : 0;
    cr_cleanup(&st);
    return rc;
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

static bool pf_json_equiv(const struct json_value *a,
                          const struct json_value *b);

/* JSON_ARR case of pf_json_equiv, split out to keep the dispatcher's own
 * complexity under the cap. */
static bool pf_json_equiv_arr(const struct json_value *a,
                              const struct json_value *b)
{
    if (a->num_children != b->num_children)
        return false;
    for (size_t i = 0; i < a->num_children; i++)
        if (!pf_json_equiv(&a->children[i], &b->children[i]))
            return false;
    return true;
}

/* JSON_OBJ case of pf_json_equiv, split out to keep the dispatcher's own
 * complexity under the cap. */
static bool pf_json_equiv_obj(const struct json_value *a,
                              const struct json_value *b)
{
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
        return pf_json_equiv_arr(a, b);
    case JSON_OBJ:
        return pf_json_equiv_obj(a, b);
    }
    return false;
}

/* Scratch-run state threaded through cmd_selftest's numbered checks. */
struct cst_state {
    char fixture[PF_PATH_CAP];
    char pkg[PF_PATH_CAP], key[PF_PATH_CAP], store_a[PF_PATH_CAP],
         store_b[PF_PATH_CAP], report[PF_PATH_CAP], dplan[PF_PATH_CAP],
         fastcache[PF_PATH_CAP], report2[PF_PATH_CAP];
    char pubkey[256];
    char root_hex[65];
    char store_a_abs[PF_PATH_CAP];
    char def_path[PF_PATH_CAP], census_out[PF_PATH_CAP];
    char store_a_label[PF_PATH_CAP], store_a_root[PF_PATH_CAP];
    char report_path[PF_PATH_CAP];
};

/* The scratch root must stay under test-tmp/ (gitignored scratch; never a
 * real datadir), and the tiny-lines fixture must be readable. */
static int cst_validate_scratch(const char *repo, const char *scratch,
                                struct cst_state *st)
{
    if (strncmp(scratch, "test-tmp/", 9) != 0 &&
        strstr(scratch, "/test-tmp/") == NULL)
        LOG_ERR(PF_LOG, "selftest scratch %s must live under test-tmp/",
                scratch);
    if (snprintf(st->fixture, sizeof(st->fixture),
                 "%s/tests/harness/fixtures/zcode/tiny-lines", repo) >=
        (int)sizeof(st->fixture))
        LOG_ERR(PF_LOG, "fixture path overflow");
    if (access(st->fixture, R_OK) != 0)
        LOG_ERR(PF_LOG, "fixture %s not readable", st->fixture);
    return 0;
}

/* Fresh scratch. */
static int cst_fresh_scratch(const char *scratch)
{
    char *rm_argv[] = {(char *)"rm", (char *)"-rf", (char *)scratch, NULL};
    char devnull[16];
    if (pf_spawn(rm_argv, NULL, 0, devnull, sizeof(devnull)) != 0)
        LOG_ERR(PF_LOG, "cannot clear scratch %s", scratch);
    if (!pf_mkdir_p(scratch))
        return 1;
    return 0;
}

static int cst_build_paths(const char *scratch, struct cst_state *st)
{
    if (snprintf(st->pkg, sizeof(st->pkg), "%s/pkg", scratch) >=
            (int)sizeof(st->pkg) ||
        snprintf(st->key, sizeof(st->key), "%s/key", scratch) >=
            (int)sizeof(st->key) ||
        snprintf(st->store_a, sizeof(st->store_a), "%s/storeA", scratch) >=
            (int)sizeof(st->store_a) ||
        snprintf(st->store_b, sizeof(st->store_b), "%s/storeB", scratch) >=
            (int)sizeof(st->store_b) ||
        snprintf(st->report, sizeof(st->report), "%s/report.json",
                scratch) >= (int)sizeof(st->report) ||
        snprintf(st->dplan, sizeof(st->dplan), "%s/plan.json", scratch) >=
            (int)sizeof(st->dplan) ||
        snprintf(st->fastcache, sizeof(st->fastcache), "%s/fastcache",
                scratch) >= (int)sizeof(st->fastcache) ||
        snprintf(st->report2, sizeof(st->report2), "%s/report2.json",
                scratch) >= (int)sizeof(st->report2))
        LOG_ERR(PF_LOG, "selftest path overflow");
    return 0;
}

static int cst_copy_fixture(const struct cst_state *st)
{
    char *cp_argv[] = {(char *)"cp", (char *)"-r", (char *)st->fixture,
                       (char *)st->pkg, NULL};
    char out[256];
    if (pf_spawn(cp_argv, NULL, 0, out, sizeof(out)) != 0)
        LOG_ERR(PF_LOG, "fixture copy failed: %s", out);
    return 0;
}

/* Throwaway key: the signer's keygen mode. */
static int cst_generate_key(const char *bin_dir, const char *key,
                            char pubkey[256])
{
    char bin[PF_PATH_CAP];
    if (snprintf(bin, sizeof(bin), "%s/zclassic23-package-sign", bin_dir) >=
        (int)sizeof(bin))
        LOG_ERR(PF_LOG, "signer path overflow");
    char *argv[] = {bin, (char *)"--generate", (char *)key, NULL};
    if (pf_spawn(argv, NULL, 0, pubkey, 256) != 0)
        LOG_ERR(PF_LOG, "keygen failed");
    size_t len = strlen(pubkey);
    while (len && isspace((unsigned char)pubkey[len - 1]))
        pubkey[--len] = '\0';
    if (strlen(pubkey) != 66)
        LOG_ERR(PF_LOG, "keygen returned no pubkey");
    return 0;
}

static void cst_fill_run_args(struct run_args *args, const struct cst_state *st,
                              const char *bin_dir, const char *report_path)
{
    memset(args, 0, sizeof(*args));
    args->package_dir = st->pkg;
    args->key_file = st->key;
    args->publisher_pubkey = st->pubkey;
    args->store_a = st->store_a;
    args->store_b = st->store_b;
    args->report_path = report_path;
    args->dep_plan_path = st->dplan;
    args->fast_cache_dir = st->fastcache;
    args->bin_dir = bin_dir;
    args->chain_id = "zclassic-main";
    args->kind = "ai";
    args->publisher_sequence = 1;
    args->cutoff_height = 1;
    args->cutoff_mtp = 1700000000;
}

static int cst_run_first(const char *bin_dir, const struct cst_state *st)
{
    struct run_args args;
    cst_fill_run_args(&args, st, bin_dir, st->report);
    int rc = cmd_run(&args);
    if (rc != 0)
        LOG_ERR(PF_LOG, "selftest: factory run failed (rc=%d)", rc);
    return 0;
}

/* Assert the report: every step ok, reproduced both sides. */
static int cst_assert_report(const char *report)
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
    bool pass = ok && json_get_bool(ok) && ra && json_get_bool(ra) && rb &&
                json_get_bool(rb);
    json_free(&doc);
    if (!pass)
        LOG_ERR(PF_LOG, "selftest: report assertions failed");
    printf("selftest: gate/publish/reproduce/report ok (report=%s)\n",
           report);
    return 0;
}

/* The exact dependency plan exists, parses as zcl.dep_plan.v1, and the
 * report's plan hash matches the plan file bytes. */
static int cst_assert_dep_plan(const char *report)
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
        pass = pf_read_file(path_buf, PF_CLI_STDOUT_CAP, &plan, &plan_len);
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
    return 0;
}

/* The fast-cache re-run must turn every confined rebuild into a cache hit,
 * checked from the two already-parsed report documents. */
static int cst_assert_fast_cache_hits(const struct json_value *d1,
                                      const struct json_value *d2)
{
    const struct json_value *fc2 = json_get(d2, "fast_cache");
    const struct json_value *fc2_hits = json_get(fc2, "hits");
    const struct json_value *fc2_misses = json_get(fc2, "misses");
    const struct json_value *fc1 = json_get(d1, "fast_cache");
    const struct json_value *fc1_misses = json_get(fc1, "misses");
    bool pass = fc2_hits && fc2_misses && fc1_misses &&
               json_get_int(fc2_hits) >= 3 && json_get_int(fc2_misses) == 0 &&
               json_get_int(fc1_misses) >= 2;
    if (!pass)
        LOG_ERR(PF_LOG, "selftest: fast cache did not turn the re-run into "
                "all hits");
    return 0;
}

/* Second full run against the SAME fast cache with only the stores wiped:
 * every confined rebuild must now be a cache hit, and the report must
 * equal run 1's modulo the volatile keys. */
static int cst_run_second_and_compare(const char *bin_dir,
                                      const struct cst_state *st)
{
    char *rm_argv[] = {(char *)"rm", (char *)"-rf", (char *)st->store_a,
                       (char *)st->store_b, NULL};
    char devnull[16];
    if (pf_spawn(rm_argv, NULL, 0, devnull, sizeof(devnull)) != 0)
        LOG_ERR(PF_LOG, "selftest: store wipe failed");
    struct run_args args2;
    cst_fill_run_args(&args2, st, bin_dir, st->report2);
    int rc = cmd_run(&args2);
    if (rc != 0)
        LOG_ERR(PF_LOG, "selftest: factory re-run failed (rc=%d)", rc);
    uint8_t *t1 = NULL, *t2 = NULL;
    size_t l1 = 0, l2 = 0;
    if (!pf_read_file(st->report, PF_CLI_STDOUT_CAP, &t1, &l1) ||
        !pf_read_file(st->report2, PF_CLI_STDOUT_CAP, &t2, &l2))
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
    int rc2 = cst_assert_fast_cache_hits(&d1, &d2);
    if (rc2 == 0)
        pass = pf_json_equiv(&d1, &d2);
    json_free(&d1);
    json_free(&d2);
    if (rc2 != 0)
        return rc2;
    if (!pass)
        LOG_ERR(PF_LOG, "selftest: cached re-run report diverges from the "
                "clean run (beyond volatile keys)");
    printf("selftest: fast cache ok (re-run all hits, reports equal "
           "modulo volatile keys)\n");
    return 0;
}

/* Census intake, step 1: read the package_root out of the first report. */
static int cst_read_package_root(const char *report, char root_hex[65])
{
    uint8_t *rtext = NULL;
    size_t rlen = 0;
    if (!pf_read_file(report, PF_CLI_STDOUT_CAP, &rtext, &rlen))
        LOG_ERR(PF_LOG, "selftest: report re-read failed");
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
    (void)snprintf(root_hex, 65, "%s", r);
    json_free(&doc);
    return 0;
}

/* Census intake, step 2: a scratch def with ONLY the package line,
 * pointing at scratch store A by LABEL — the end-to-end proof that the
 * label form resolves, and that no absolute path is ever written into a
 * scopes.def, not even a scratch one. */
static int cst_build_census_def(const char *scratch, struct cst_state *st)
{
    if (!realpath(st->store_a, st->store_a_abs))
        LOG_ERR(PF_LOG, "selftest: realpath %s: %s", st->store_a,
                strerror(errno));
    if (snprintf(st->def_path, sizeof(st->def_path), "%s/scopes.def",
                scratch) >= (int)sizeof(st->def_path) ||
        snprintf(st->census_out, sizeof(st->census_out), "%s/census",
                scratch) >= (int)sizeof(st->census_out))
        LOG_ERR(PF_LOG, "selftest path overflow");
    char lerr[PF_ERROR_CAP] = {0};
    if (!pf_store_label(st->store_a_abs, st->store_a_label,
                        sizeof(st->store_a_label), lerr, sizeof(lerr)))
        LOG_ERR(PF_LOG, "selftest: store label: %s", lerr);
    size_t root_len = strlen(st->store_a_abs) - strlen(st->store_a_label);
    if (root_len < 2u || root_len >= sizeof(st->store_a_root))
        LOG_ERR(PF_LOG, "selftest: store '%s' has no parent directory",
                st->store_a_abs);
    memcpy(st->store_a_root, st->store_a_abs, root_len - 1u); /* drop '/' */
    st->store_a_root[root_len - 1u] = '\0';
    size_t line_cap = strlen(st->store_a_label) + 160u;
    char *line = zcl_malloc(line_cap, "factory.selftest.def");
    if (!line)
        LOG_ERR(PF_LOG, "def line alloc");
    int n = snprintf(line, line_cap,
                     "package fixture/tiny-lines | root %s | store %s | "
                     "kind ai | spdx MIT\n", st->root_hex, st->store_a_label);
    if (n <= 0 || (size_t)n >= line_cap ||
        !pf_write_atomic(st->def_path, (const uint8_t *)line, (size_t)n)) {
        free(line);
        LOG_ERR(PF_LOG, "selftest: cannot write scratch def");
    }
    free(line);
    return 0;
}

static int cst_run_census(const char *repo, const char *bin_dir,
                          const struct cst_state *st)
{
    char bin[PF_PATH_CAP];
    if (snprintf(bin, sizeof(bin), "%s/corpus-census", bin_dir) >=
        (int)sizeof(bin))
        LOG_ERR(PF_LOG, "census path overflow");
    char *argv[] = {bin,
                    (char *)"--repo", (char *)repo,
                    (char *)"--def", (char *)st->def_path,
                    (char *)"--out", (char *)st->census_out,
                    (char *)"--store-root", (char *)st->store_a_root,
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
    return 0;
}

/* Assert the census counted the package. */
static int cst_assert_census(struct cst_state *st)
{
    if (snprintf(st->report_path, sizeof(st->report_path),
                 "%s/report-000001.json", st->census_out) >=
        (int)sizeof(st->report_path))
        LOG_ERR(PF_LOG, "selftest path overflow");
    uint8_t *text = NULL;
    size_t len = 0;
    if (!pf_read_file(st->report_path, PF_CLI_STDOUT_CAP, &text, &len))
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
    if (scopes && scopes->type == JSON_ARR && scopes->num_children == 1) {
        const struct json_value *scope = json_at(scopes, 0);
        const struct json_value *counted = json_get(scope, "counted");
        const struct json_value *tloc = json_get(scope, "test_loc_would_be");
        const struct json_value *repro = json_get(scope, "reproduced");
        pass = counted && json_get_bool(counted) && tloc &&
               json_get_int(tloc) > 0 && repro && json_get_bool(repro);
    }
    json_free(&doc);
    if (!pass)
        LOG_ERR(PF_LOG, "selftest: package NOT counted with test LOC and "
                "reproduction in the census");
    printf("selftest: census intake ok (package counted, test_loc>0, "
           "reproduced)\n");
    return 0;
}

static int cmd_selftest(const char *repo, const char *scratch,
                        const char *bin_dir)
{
    char error[PF_ERROR_CAP];
    struct cst_state st;
    memset(&st, 0, sizeof(st));
    int rc;
    if ((rc = cst_validate_scratch(repo, scratch, &st))) return rc;
    if ((rc = cst_fresh_scratch(scratch))) return rc;
    if ((rc = cst_build_paths(scratch, &st))) return rc;
    if ((rc = cst_copy_fixture(&st))) return rc;
    if ((rc = cst_generate_key(bin_dir, st.key, st.pubkey))) return rc;
    if ((rc = cst_run_first(bin_dir, &st))) return rc;
    if ((rc = cst_assert_report(st.report))) return rc;
    if ((rc = cst_assert_dep_plan(st.report))) return rc;
    if ((rc = cst_run_second_and_compare(bin_dir, &st))) return rc;
    if ((rc = cst_read_package_root(st.report, st.root_hex))) return rc;
    if ((rc = cst_build_census_def(scratch, &st))) return rc;
    if ((rc = cst_run_census(repo, bin_dir, &st))) return rc;
    if ((rc = cst_assert_census(&st))) return rc;
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
        "      [--register-corpus --census-def contexts/commons/corpus/scopes.def]\n"
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

struct main_opts {
    const char *package_dir, *key_file, *pubkey, *store_a, *store_b, *report,
               *bin_dir, *census_def, *seed_file, *chain_id, *kind,
               *dep_name, *dep_root, *repo, *scratch, *dep_plan, *fast_cache;
    char dep_plan_default[PF_PATH_CAP];
    char fast_cache_default[PF_PATH_CAP];
    uint64_t sequence;
    uint64_t cutoff_height;
    int64_t cutoff_mtp;
    bool register_corpus;
};

/* Table-driven dispatch for the plain string-valued --key value flags, so
 * matching a flag name is a loop over data rather than a long if/else-if
 * chain. */
static bool main_apply_string_flag(struct main_opts *opts, const char *keyb,
                                   const char *value)
{
    static const struct {
        const char *flag;
        size_t offset;
    } table[] = {
        {"--package", offsetof(struct main_opts, package_dir)},
        {"--publisher-key-file", offsetof(struct main_opts, key_file)},
        {"--publisher-pubkey", offsetof(struct main_opts, pubkey)},
        {"--store-a", offsetof(struct main_opts, store_a)},
        {"--store-b", offsetof(struct main_opts, store_b)},
        {"--report", offsetof(struct main_opts, report)},
        {"--dep-plan", offsetof(struct main_opts, dep_plan)},
        {"--fast-cache", offsetof(struct main_opts, fast_cache)},
        {"--bin-dir", offsetof(struct main_opts, bin_dir)},
        {"--census-def", offsetof(struct main_opts, census_def)},
        {"--signer-seed-file", offsetof(struct main_opts, seed_file)},
        {"--chain-id", offsetof(struct main_opts, chain_id)},
        {"--kind", offsetof(struct main_opts, kind)},
        {"--dep-name", offsetof(struct main_opts, dep_name)},
        {"--dep-root", offsetof(struct main_opts, dep_root)},
        {"--repo", offsetof(struct main_opts, repo)},
        {"--scratch", offsetof(struct main_opts, scratch)},
    };
    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if (strcmp(keyb, table[i].flag) == 0) {
            *(const char **)((char *)opts + table[i].offset) = value;
            return true;
        }
    }
    return false;
}

/* The remaining flags need numeric parsing/validation rather than a plain
 * string assignment. */
static bool main_apply_numeric_flag(struct main_opts *opts, const char *keyb,
                                    const char *value, bool *bad)
{
    if (strcmp(keyb, "--publisher-sequence") == 0) {
        *bad = !parse_u64(value, &opts->sequence) || !opts->sequence;
        return true;
    }
    if (strcmp(keyb, "--cutoff-height") == 0) {
        *bad = !parse_u64(value, &opts->cutoff_height) || !opts->cutoff_height;
        return true;
    }
    if (strcmp(keyb, "--cutoff-mtp") == 0) {
        *bad = !parse_i64(value, &opts->cutoff_mtp) || opts->cutoff_mtp <= 0;
        return true;
    }
    return false;
}

/* Generic --key value / --key=value parsing. */
static int main_parse_args(int argc, char **argv, struct main_opts *opts)
{
    *opts = (struct main_opts){
        .bin_dir = "build/bin",
        .census_def = "contexts/commons/corpus/scopes.def",
        .chain_id = "zclassic-main",
        .kind = "ai",
        .repo = ".",
        .scratch = "test-tmp/factory-selftest",
        .sequence = 1,
        .cutoff_height = 1,
        .cutoff_mtp = 1700000000,
    };
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
                opts->register_corpus = true;
                continue;
            }
            if (i + 1 >= argc) {
                usage(stderr);
                return 2;
            }
            value = argv[++i];
        }
        if (main_apply_string_flag(opts, keyb, value))
            continue;
        bool bad = false;
        if (main_apply_numeric_flag(opts, keyb, value, &bad)) {
            if (bad) return 2;
            continue;
        }
        usage(stderr);
        return 2;
    }
    return 0;
}

/* Default: the report's sibling, <name>.report.json → <name>.plan.json. */
static bool main_default_dep_plan(const char *report, char *buf, size_t cap)
{
    static const char suffix[] = ".report.json";
    size_t rl = strlen(report);
    size_t sl = sizeof(suffix) - 1u;
    if (rl > sl && strcmp(report + rl - sl, suffix) == 0) {
        if (rl - sl + sizeof(".plan.json") > cap)
            return false;
        memcpy(buf, report, rl - sl);
        memcpy(buf + rl - sl, ".plan.json", sizeof(".plan.json"));
        return true;
    }
    if (snprintf(buf, cap, "%s.plan.json", report) >= (int)cap)
        return false;
    return true;
}

/* Default per-TU object cache: $XDG_CACHE_HOME/zclassic23/fast-obj, else
 * $HOME/.cache/zclassic23/fast-obj. An explicit empty --fast-cache=
 * disables the cache (no default). */
static const char *main_default_fast_cache(char *buf, size_t cap)
{
    const char *base = getenv("XDG_CACHE_HOME");
    int n;
    if (base && base[0])
        n = snprintf(buf, cap, "%s/zclassic23/fast-obj", base);
    else {
        const char *home = getenv("HOME");
        n = home ? snprintf(buf, cap, "%s/.cache/zclassic23/fast-obj", home)
                 : -1;
    }
    if (n > 0 && (size_t)n < cap)
        return buf;
    return NULL;
}

static int main_run_mode(struct main_opts *opts)
{
    if (!opts->package_dir || !opts->key_file || !opts->pubkey ||
        !opts->store_a || !opts->store_b || !opts->report ||
        (opts->register_corpus && !opts->census_def)) {
        usage(stderr);
        return 2;
    }
    if (!opts->dep_plan) {
        if (!main_default_dep_plan(opts->report, opts->dep_plan_default,
                                   sizeof(opts->dep_plan_default)))
            return 2;
        opts->dep_plan = opts->dep_plan_default;
    }
    if (!opts->fast_cache) {
        const char *fc = main_default_fast_cache(
            opts->fast_cache_default, sizeof(opts->fast_cache_default));
        if (fc)
            opts->fast_cache = fc;
    }
    if (opts->fast_cache && !opts->fast_cache[0])
        opts->fast_cache = NULL;
    struct run_args args = {
        .package_dir = opts->package_dir,
        .key_file = opts->key_file,
        .publisher_pubkey = opts->pubkey,
        .store_a = opts->store_a,
        .store_b = opts->store_b,
        .report_path = opts->report,
        .dep_plan_path = opts->dep_plan,
        .fast_cache_dir = opts->fast_cache,
        .bin_dir = opts->bin_dir,
        .census_def = opts->census_def,
        .signer_seed_file = opts->seed_file,
        .chain_id = opts->chain_id,
        .kind = opts->kind,
        .publisher_sequence = opts->sequence,
        .cutoff_height = opts->cutoff_height,
        .cutoff_mtp = opts->cutoff_mtp,
        .register_corpus = opts->register_corpus,
    };
    return cmd_run(&args);
}

static int main_pin_dep_mode(const struct main_opts *opts)
{
    if (!opts->package_dir || !opts->dep_name || !opts->dep_root) {
        usage(stderr);
        return 2;
    }
    return cmd_pin_dep(opts->package_dir, opts->dep_name, opts->dep_root);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(stderr);
        return 2;
    }
    const char *mode = argv[1];
    struct main_opts opts;
    int pe = main_parse_args(argc, argv, &opts);
    if (pe) return pe;
    if (strcmp(opts.kind, "human") != 0 && strcmp(opts.kind, "ai") != 0 &&
        strcmp(opts.kind, "import") != 0) {
        usage(stderr);
        return 2;
    }

    if (strcmp(mode, "run") == 0)
        return main_run_mode(&opts);
    if (strcmp(mode, "pin-dep") == 0)
        return main_pin_dep_mode(&opts);
    if (strcmp(mode, "selftest") == 0)
        return cmd_selftest(opts.repo, opts.scratch, opts.bin_dir);
    usage(stderr);
    return 2;
}
