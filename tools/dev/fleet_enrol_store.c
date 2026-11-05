/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The machine roster, the spent-invite nonce list, and the one
 *          restricted ssh line the bridge adds.
 *          See tools/dev/fleet_enrol.h for the contract.
 *
 * The roster is an append-only text file of operator-sealed lines under
 * platform_state_root()/fleet/. Append-only because a roster that can be
 * rewritten in place is a roster whose history nobody can check, and
 * text-of-signed-records because then the file itself carries no authority:
 * every line is re-verified against the operator public key on every read,
 * and a line this key did not seal is counted as unverifiable and never
 * rendered. Editing the file by hand can therefore delete rows, but cannot
 * invent one.
 *
 * The nonce list is the replay refusal. One spent invite nonce per line, in
 * hex. A nonce is spent only AFTER the roster line is durable, so a refusal
 * later in admission can never burn an invite the owner then cannot use.
 */

#include "fleet_enrol.h"

#include "base/hex.h"
#include "crypto/sha256.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/positioned_file.h"
#include "platform/directory_transaction.h"
#include "platform/private_file.h"
#include "platform/time_compat.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLEET_DOMAIN "fleet-enrol"
#define FLEET_ROSTER_LEAF "machines.roster"
#define FLEET_NONCE_LEAF "invites.spent"
#define FLEET_HEAD_LEAF "roster.head"
#define FLEET_PIN_LEAF "operator.pin"

/* Ceilings on the two files this module reads whole. The roster cannot
 * usefully exceed one line per assignable relay port, and the nonce list is
 * one 33-byte line per invite ever spent; both refuse a pasted blob rather
 * than swallowing it. */
#define FLEET_ROSTER_MAX_BYTES \
    ((size_t)FLEET_ENROL_ROSTER_MAX * (size_t)FLEET_ENROL_MACHINE_TEXT_MAX)
#define FLEET_NONCE_MAX_BYTES (64u * 1024u)
/* An authorized_keys file this box will read whole before appending to it.
 * Larger than any real one and small enough that reading it is bounded. */
#define FLEET_BRIDGE_MAX_BYTES (256u * 1024u)

static void fe_why(const char **why, const char *token)
{
    if (why) *why = token;
}

/* Read one whole state file into `buf`. A missing file is not an error: it
 * is an empty roster, which is what a manager has before the first box
 * joins. `len` is set to the byte count read, always NUL-terminated. */
static bool fe_slurp_mode(const char *leaf, char *buf, size_t cap, size_t *len,
                          const char **why, bool readonly)
{
    struct platform_positioned_file file;
    char path[FLEET_ENROL_PATH_MAX];
    uint64_t size = 0;
    *len = 0;
    buf[0] = '\0';
    if (!(readonly ? fleet_enrol_state_path_existing(leaf, path, sizeof(path)) :
                      fleet_enrol_state_path(leaf, path, sizeof(path)))) {
        fe_why(why, FLEET_ENROL_WHY_STATE_ROOT);
        return false;
    }
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return true;
    bool ok = platform_positioned_file_size(&file, &size) && size < cap;
    if (ok && size)
        ok = platform_positioned_file_read(&file, buf, (size_t)size, 0) ==
             (int64_t)size;
    platform_positioned_file_close(&file);
    if (!ok) {
        fe_why(why, FLEET_ENROL_WHY_ROSTER_UNREADABLE);
        LOG_WARN(FLEET_DOMAIN,
                 "cannot read the fleet state file whole: path=%s", path);
        return false;
    }
    *len = (size_t)size;
    buf[*len] = '\0';
    return true;
}

static bool fe_slurp(const char *leaf, char *buf, size_t cap, size_t *len,
                     const char **why)
{ return fe_slurp_mode(leaf, buf, cap, len, why, false); }

/* Append one NUL-terminated line plus its newline, under an exclusive
 * whole-file lock so two admissions on one box cannot interleave halves of
 * two lines. */
static bool fe_append_line(const char *leaf, const char *line,
                           const char *unwritable_why, const char **why)
{
    struct platform_private_file file;
    char path[FLEET_ENROL_PATH_MAX];
    char buffer[FLEET_ENROL_MACHINE_TEXT_MAX + 2];
    uint64_t size = 0;
    int n = snprintf(buffer, sizeof(buffer), "%s\n", line);
    if (n <= 0 || (size_t)n >= sizeof(buffer)) {
        fe_why(why, FLEET_ENROL_WHY_ARGUMENTS);
        return false;
    }
    if (!fleet_enrol_state_path(leaf, path, sizeof(path))) {
        fe_why(why, FLEET_ENROL_WHY_STATE_ROOT);
        return false;
    }
    platform_private_file_init(&file);
    if (!platform_private_file_open_locked_create_wait(path, &file)) {
        fe_why(why, unwritable_why);
        return false;
    }
    bool ok = platform_private_file_size(&file, &size) &&
              platform_private_file_write_at(&file, buffer, (size_t)n, size) &&
              platform_private_file_authority_flush(&file);
    platform_private_file_close(&file);
    if (!ok) {
        fe_why(why, unwritable_why);
        LOG_WARN(FLEET_DOMAIN, "cannot append one fleet line: path=%s", path);
        return false;
    }
    return true;
}

/* Walk NUL-terminated text line by line, calling `visit` on each non-empty
 * line. The buffer is modified in place (each newline becomes a NUL). */
static void fe_each_line(char *text, void (*visit)(char *, void *), void *user)
{
    char *at = text;
    while (at && *at) {
        char *end = strchr(at, '\n');
        if (end) *end = '\0';
        if (*at) visit(at, user);
        at = end ? end + 1 : NULL;
    }
}

/* ── roster ─────────────────────────────────────────────────────────────── */

struct fe_walk {
    const uint8_t *operator_pubkey;
    const char *name;                /* NULL when not answering "taken?" */
    const uint8_t *box_pubkey;       /* NULL when not answering "same box?" */
    struct fleet_roster_scan *scan;
    bool used[FLEET_ENROL_ROSTER_MAX];
    void (*visit)(const struct fleet_machine *, void *);
    void *user;
    struct fleet_machine machine;    /* one row at a time; never an array */
};

static void fe_walk_line(char *line, void *user)
{
    struct fe_walk *w = user;
    const char *why = NULL;
    uint16_t port = 0;
    if (!fleet_machine_parse(line, w->operator_pubkey, &w->machine, &why)) {
        w->scan->unverifiable++;
        return;
    }
    w->scan->rows++;
    port = w->machine.relay_port;
    if (port >= FLEET_ENROL_PORT_FIRST && port <= FLEET_ENROL_PORT_LAST)
        w->used[port - FLEET_ENROL_PORT_FIRST] = true;
    if (w->box_pubkey &&
        memcmp(w->machine.receipt.box_pubkey, w->box_pubkey,
               FLEET_ENROL_PUBKEY_BYTES) == 0) {
        /* A box re-enrolling keeps its identity and its port. That is what
         * makes re-running `fleet admit` after a lost reply idempotent
         * rather than a second grant under a second port. */
        w->scan->same_box = true;
        w->scan->existing_port = port;
    } else if (w->name && strcmp(w->machine.receipt.invite.name, w->name) == 0) {
        w->scan->name_taken = true;
    }
    if (w->visit) w->visit(&w->machine, w->user);
}

static bool fe_roster_walk(struct fe_walk *w, const char **why, bool readonly)
{
    char *text = zcl_malloc(FLEET_ROSTER_MAX_BYTES + 1u, "fleet-roster");
    size_t len = 0;
    memset(w->scan, 0, sizeof(*w->scan));
    memset(w->used, 0, sizeof(w->used));
    if (!text) {
        fe_why(why, FLEET_ENROL_WHY_ROSTER_UNREADABLE);
        return false;
    }
    if (!fe_slurp_mode(FLEET_ROSTER_LEAF, text, FLEET_ROSTER_MAX_BYTES + 1u, &len,
                       why, readonly)) {
        free(text);
        return false;
    }
    fe_each_line(text, fe_walk_line, w);
    free(text);
    for (int i = 0; i < FLEET_ENROL_ROSTER_MAX; ++i) {
        if (!w->used[i]) {
            w->scan->next_port = (uint16_t)(FLEET_ENROL_PORT_FIRST + i);
            break;
        }
    }
    if (w->scan->unverifiable)
        LOG_WARN(FLEET_DOMAIN,
                 "fleet roster carries %u line(s) this operator key did not "
                 "seal; they are counted, never listed",
                 (unsigned)w->scan->unverifiable);
    return true;
}

static bool fe_roster_query(const uint8_t *operator_pubkey, const char *name,
                            const uint8_t *box_pubkey,
                            void (*visit)(const struct fleet_machine *, void *),
                            void *user, struct fleet_roster_scan *out,
                            const char **why, bool readonly)
{
    struct fe_walk w = {0};
    w.operator_pubkey = operator_pubkey;
    w.name = name;
    w.box_pubkey = box_pubkey;
    w.scan = out;
    w.visit = visit;
    w.user = user;
    fe_why(why, NULL);
    return fe_roster_walk(&w, why, readonly);
}

bool fleet_roster_scan(const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                       const char *name,
                       const uint8_t box_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                       struct fleet_roster_scan *out, const char **why)
{
    return fe_roster_query(operator_pubkey, name, box_pubkey, NULL, NULL,
                           out, why, false);
}

bool fleet_roster_each(const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                       void (*visit)(const struct fleet_machine *, void *),
                       void *user, struct fleet_roster_scan *out,
                       const char **why)
{
    return fe_roster_query(operator_pubkey, NULL, NULL, visit, user,
                           out, why, false);
}

struct fe_raw_walk {
    void (*visit)(const char *line, void *user);
    void *user;
};

static void fe_raw_line(char *line, void *user)
{
    struct fe_raw_walk *w = user;
    /* A line longer than one machine line can be is not one; it is never
     * handed on, so a pasted blob cannot reach a verifier. */
    if (strlen(line) < (size_t)FLEET_ENROL_MACHINE_TEXT_MAX)
        w->visit(line, w->user);
}

bool fleet_roster_each_line(void (*visit)(const char *line, void *user),
                            void *user, const char **why)
{
    struct fe_raw_walk w = { visit, user };
    size_t len = 0;
    char *text = NULL;
    fe_why(why, NULL);
    if (!visit) {
        fe_why(why, FLEET_ENROL_WHY_ARGUMENTS);
        return false;
    }
    text = zcl_malloc(FLEET_ROSTER_MAX_BYTES + 1u, "fleet-roster-lines");
    if (!text) {
        fe_why(why, FLEET_ENROL_WHY_ROSTER_UNREADABLE);
        return false;
    }
    if (!fe_slurp(FLEET_ROSTER_LEAF, text, FLEET_ROSTER_MAX_BYTES + 1u, &len,
                  why)) {
        free(text);
        return false;
    }
    fe_each_line(text, fe_raw_line, &w);
    free(text);
    return true;
}

bool fleet_roster_append(const char *line, const char **why)
{
    fe_why(why, NULL);
    return fe_append_line(FLEET_ROSTER_LEAF, line,
                          FLEET_ENROL_WHY_ROSTER_UNWRITABLE, why);
}

/* ── the state lock ───────────────────────────────────────────────────────
 *
 * Every read-compare-replace on the head and the pin, and the row import's
 * revoked-head check plus its append, run under ONE exclusive advisory lock
 * on fleet.lock in the private fleet directory. Without it two imports can
 * both read held seq N, the higher publishes, and the lower then overwrites
 * it: a sequence rollback that undoes the higher head's revocations. The lock
 * is bounded-wait; failing to take it refuses (fail closed) and never
 * proceeds unlocked. */

#define FLEET_LOCK_LEAF "fleet.lock"
#define FLEET_LOCK_WAIT_MS 5000
#define FLEET_LOCK_POLL_MS 10

#ifdef ZCL_TESTING
int fleet_enrol_test_lock_wait_ms = FLEET_LOCK_WAIT_MS;
void (*fleet_enrol_test_after_check)(void) = NULL;
bool fleet_enrol_test_fail_pin_write = false;
bool fleet_enrol_test_fail_dir_flush = false;
#define FE_LOCK_WAIT_MS fleet_enrol_test_lock_wait_ms
static void fe_test_after_check(void)
{
    if (fleet_enrol_test_after_check)
        fleet_enrol_test_after_check();
}
#else
#define FE_LOCK_WAIT_MS FLEET_LOCK_WAIT_MS
static void fe_test_after_check(void) {}
#endif

struct fe_state_lock {
    struct platform_directory_transaction dir;
    struct platform_directory_lock lock;
};

static void fe_state_unlock(struct fe_state_lock *l)
{
    platform_directory_lock_release(&l->lock);
    platform_directory_transaction_close(&l->dir);
}

static bool fe_state_lock_take(struct fe_state_lock *l, const char **why)
{
    char path[FLEET_ENROL_PATH_MAX];
    char *slash;
    int waited = 0;
    enum platform_directory_result r;
    platform_directory_transaction_init(&l->dir);
    platform_directory_lock_init(&l->lock);
    fe_why(why, FLEET_ENROL_WHY_STATE_LOCK);
    if (!fleet_enrol_state_path(FLEET_LOCK_LEAF, path, sizeof(path))) {
        fe_why(why, FLEET_ENROL_WHY_STATE_ROOT);
        return false;
    }
    slash = strrchr(path, '/');
#ifdef _WIN32
    char *bslash = strrchr(path, '\\');
    if (bslash && (!slash || bslash > slash)) slash = bslash;
#endif
    if (!slash)
        LOG_FAIL(FLEET_DOMAIN, "fleet lock path has no directory part");
    *slash = '\0';
    if (!platform_directory_transaction_open(&l->dir, path))
        LOG_FAIL(FLEET_DOMAIN,
                 "cannot open the fleet state directory to lock it");
    do {
        r = platform_directory_lock_acquire(&l->dir, FLEET_LOCK_LEAF, true,
                                            PLATFORM_DIRECTORY_LOCK_EXCLUSIVE,
                                            &l->lock);
        if (r == PLATFORM_DIRECTORY_OK) {
            fe_why(why, NULL);
            return true;
        }
        if (r != PLATFORM_DIRECTORY_REFUSED)
            break;
        platform_sleep_ms(FLEET_LOCK_POLL_MS);
        waited += FLEET_LOCK_POLL_MS;
    } while (waited < FE_LOCK_WAIT_MS);
    platform_directory_transaction_close(&l->dir);
    LOG_FAIL(FLEET_DOMAIN, "fleet_state_locked: cannot take the fleet state "
             "lock; refusing rather than racing");
}


/* ── strict state files: the roster head and the operator pin ─────────────
 *
 * fe_slurp treats every failure to open as "no file yet", which is right
 * for a roster that does not exist and WRONG for a revocation list or a
 * pin: an unreadable head must never read as "nothing revoked", and an
 * unreadable pin must never read as "never pinned". These reads tell the
 * two apart: only a path that is truly absent is absent. */

enum fe_read { FE_READ_OK = 0, FE_READ_ABSENT, FE_READ_BAD };

static enum fe_read fe_read_strict_mode(const char *leaf, char *buf, size_t cap,
                                        size_t *len, bool readonly)
{
    struct platform_positioned_file file;
    char path[FLEET_ENROL_PATH_MAX];
    uint64_t size = 0;
    *len = 0;
    buf[0] = '\0';
    if (!(readonly ? fleet_enrol_state_path_existing(leaf, path, sizeof(path)) :
                      fleet_enrol_state_path(leaf, path, sizeof(path))))
        return FE_READ_BAD;
    if (platform_private_path_absent(path))
        return FE_READ_ABSENT;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return FE_READ_BAD;
    bool ok = platform_positioned_file_size(&file, &size) && size > 0 &&
              size < cap &&
              platform_positioned_file_read(&file, buf, (size_t)size, 0) ==
                  (int64_t)size;
    platform_positioned_file_close(&file);
    if (!ok)
        return FE_READ_BAD;
    buf[size] = '\0';
    *len = (size_t)size;
    return FE_READ_OK;
}

static enum fe_read fe_read_strict(const char *leaf, char *buf, size_t cap,
                                   size_t *len)
{ return fe_read_strict_mode(leaf, buf, cap, len, false); }

/* Flush the directory that holds `path`, so a rename into it is durable
 * before the next step of a multi-leaf transition. */
static bool fe_dir_flush(const char *path)
{
#ifdef ZCL_TESTING
    if (fleet_enrol_test_fail_dir_flush)
        return false; /* the rename already happened */
#endif
    struct platform_directory_transaction dir;
    char parent[FLEET_ENROL_PATH_MAX];
    char *slash;
    bool ok;
    if (snprintf(parent, sizeof(parent), "%s", path) >= (int)sizeof(parent))
        return false;
    slash = strrchr(parent, '/');
#ifdef _WIN32
    char *bslash = strrchr(parent, '\\');
    if (bslash && (!slash || bslash > slash)) slash = bslash;
#endif
    if (!slash)
        return false;
    *slash = '\0';
    platform_directory_transaction_init(&dir);
    if (!platform_directory_transaction_open(&dir, parent))
        return false;
    ok = platform_directory_transaction_flush(&dir);
    platform_directory_transaction_close(&dir);
    return ok;
}

/* Replace one leaf atomically: stage beside it, flush, rename over it. A
 * reader sees the old file or the new one, never half of either. */
static bool fe_replace_leaf(const char *leaf, const char *text, size_t len,
                            const char *unwritable_why, bool *changed,
                            const char **why)
{
    struct platform_private_file file;
    char path[FLEET_ENROL_PATH_MAX];
    char stage[FLEET_ENROL_PATH_MAX + 8];
    fe_why(why, unwritable_why);
    if (!fleet_enrol_state_path(leaf, path, sizeof(path))) {
        fe_why(why, FLEET_ENROL_WHY_STATE_ROOT);
        return false;
    }
    if (snprintf(stage, sizeof(stage), "%s.stage", path) >= (int)sizeof(stage))
        LOG_FAIL(FLEET_DOMAIN, "fleet state path too long to stage: leaf=%s",
                 leaf);
    (void)platform_private_file_unlink_missing_ok(stage);
    platform_private_file_init(&file);
    bool renamed = false;
    bool ok = platform_private_file_create(stage, &file) &&
              platform_private_file_write_at(&file, text, len, 0) &&
              platform_private_file_truncate(&file, len) &&
              platform_private_file_authority_flush(&file) &&
              (renamed = platform_private_file_replace(&file, stage, path)) &&
              fe_dir_flush(path);
    if (renamed && changed)
        *changed = true; /* the leaf moved even if the flush then failed */
    if (!ok) {
        platform_private_file_close(&file);
        (void)platform_private_file_unlink_missing_ok(stage);
        LOG_FAIL(FLEET_DOMAIN, "cannot replace one fleet state file: leaf=%s",
                 leaf);
    }
    fe_why(why, NULL);
    return true;
}

/* ── the operator pin ─────────────────────────────────────────────────────
 *
 * The first import records which operator key this box took a roster from.
 * A later import under a different key is a changed fleet root and is
 * refused by name unless the owner says so. It is a sibling of the key
 * `fleet join` records, so the join path is untouched. */

struct fe_pin {
    bool present;
    uint8_t key[FLEET_ENROL_PUBKEY_BYTES];
};

static bool fe_pin_read(struct fe_pin *pin, const char **why, bool readonly)
{
    char text[FLEET_ENROL_PUBKEY_HEX + 2];
    size_t len = 0;
    memset(pin, 0, sizeof(*pin));
    enum fe_read r = fe_read_strict_mode(FLEET_PIN_LEAF, text, sizeof(text), &len, readonly);
    if (r == FE_READ_ABSENT)
        return true;
    if (r != FE_READ_OK || len != (size_t)(FLEET_ENROL_PUBKEY_HEX - 1) ||
        !zcl_hex_decode_lower(text, pin->key, FLEET_ENROL_PUBKEY_BYTES)) {
        memset(pin, 0, sizeof(*pin));
        fe_why(why, FLEET_ENROL_WHY_PIN_UNREADABLE);
        LOG_FAIL(FLEET_DOMAIN,
                 "the recorded fleet operator pin is not 64 lowercase hex "
                 "digits; refusing rather than pinning over it");
    }
    pin->present = true;
    return true;
}

static bool fe_pin_write(const uint8_t key[FLEET_ENROL_PUBKEY_BYTES],
                         bool *changed, const char **why)
{
    char hex[FLEET_ENROL_PUBKEY_HEX];
#ifdef ZCL_TESTING
    if (fleet_enrol_test_fail_pin_write) {
        fe_why(why, FLEET_ENROL_WHY_ROSTER_UNWRITABLE);
        return false;
    }
#endif
    zcl_hex_encode(key, FLEET_ENROL_PUBKEY_BYTES, hex);
    return fe_replace_leaf(FLEET_PIN_LEAF, hex, FLEET_ENROL_PUBKEY_HEX - 1,
                           FLEET_ENROL_WHY_ROSTER_UNWRITABLE, changed, why);
}

/* May an import sealed by `fp` go ahead? `write` says the pin must be
 * (re)written once the import has succeeded. */
static bool fe_pin_gate(const uint8_t fp[FLEET_ENROL_PUBKEY_BYTES],
                        bool confirm, bool *write, const char **why, bool readonly)
{
    struct fe_pin pin;
    *write = false;
    if (!fe_pin_read(&pin, why, readonly))
        return false;
    if (!pin.present) {
        *write = true;
        return true;
    }
    if (memcmp(pin.key, fp, FLEET_ENROL_PUBKEY_BYTES) == 0)
        return true;
    if (!confirm) {
        fe_why(why, FLEET_ENROL_WHY_ROOT_CHANGED);
        LOG_WARN(FLEET_DOMAIN,
                 "fleet_root_changed: this import is sealed by an operator "
                 "key other than the one this box pinned; pass "
                 "confirm_operator_change=yes to re-pin");
        return false;
    }
    *write = true;
    return true;
}

/* ── the roster head ────────────────────────────────────────────────────── */

/* ── the sequence high-water record ───────────────────────────────────────
 *
 * roster.head.seq is ONE small record {operator, seq, SHA-256 of the exact
 * head line}. Two leaves cannot be committed atomically, so the order is
 * fixed under the state lock: pin, then this record for the NEW head, then
 * the head. The head is trusted only when the record exists, names the
 * trusted operator, and matches the head's digest and sequence.
 *
 *   neither file          fresh box
 *   head, no record       fleet_head_hwm_unreadable (owner repair; never 0)
 *   record, head missing, corrupt or not matching the record
 *                         TORN: fleet_head_torn, admit nobody. A crash
 *                         between the record and the head lands here; only
 *                         the same head again (digest) or a higher sequence
 *                         repairs it, so an older valid head cannot roll
 *                         back a corrupted one. */

#define FLEET_HWM_LEAF "roster.head.seq"

struct fe_hwm {
    uint8_t op[FLEET_ENROL_PUBKEY_BYTES];
    uint64_t seq;
    uint8_t digest[SHA256_OUTPUT_SIZE];
};

enum fe_hwm_state { FE_HWM_OK = 0, FE_HWM_ABSENT, FE_HWM_BAD };

/* SHA-256 of the head line without its trailing newline(s). */
static void fe_head_digest(const char *line, uint8_t digest[SHA256_OUTPUT_SIZE])
{
    struct sha256_ctx ctx;
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        len--;
    sha256_init(&ctx);
    sha256_write(&ctx, (const unsigned char *)line, len);
    sha256_finalize(&ctx, digest);
}

static bool fe_hwm_parse(char *text, size_t len, struct fe_hwm *m)
{
    const size_t hex = (size_t)FLEET_ENROL_PUBKEY_BYTES * 2u;
    char *end = NULL;
    if (len < hex + 1u + 1u + 1u + hex || text[hex] != ' ' ||
        text[len - hex - 1u] != ' ')
        return false;
    text[hex] = '\0';
    text[len - hex - 1u] = '\0';
    if (!zcl_hex_decode_lower(text, m->op, FLEET_ENROL_PUBKEY_BYTES) ||
        !zcl_hex_decode_lower(text + len - hex, m->digest,
                              SHA256_OUTPUT_SIZE) ||
        text[hex + 1u] < '0' || text[hex + 1u] > '9')
        return false;
    errno = 0;
    m->seq = strtoull(text + hex + 1u, &end, 10);
    return errno == 0 && end && *end == '\0';
}

static enum fe_hwm_state fe_hwm_read_mode(struct fe_hwm *m, bool readonly)
{
    char text[256];
    size_t len = 0;
    enum fe_read r = fe_read_strict_mode(FLEET_HWM_LEAF, text, sizeof(text), &len, readonly);
    memset(m, 0, sizeof(*m));
    if (r == FE_READ_ABSENT)
        return FE_HWM_ABSENT;
    while (r == FE_READ_OK && len > 0 && text[len - 1] == '\n')
        text[--len] = '\0';
    if (r != FE_READ_OK || !fe_hwm_parse(text, len, m)) {
        memset(m, 0, sizeof(*m));
        return FE_HWM_BAD;
    }
    return FE_HWM_OK;
}

static enum fe_hwm_state fe_hwm_read(struct fe_hwm *m)
{ return fe_hwm_read_mode(m, false); }

static bool fe_hwm_write(const struct fe_hwm *m, bool *changed,
                         const char **why)
{
    char text[256];
    char op[FLEET_ENROL_PUBKEY_BYTES * 2 + 1];
    char dg[SHA256_OUTPUT_SIZE * 2 + 1];
    zcl_hex_encode(m->op, FLEET_ENROL_PUBKEY_BYTES, op);
    zcl_hex_encode(m->digest, SHA256_OUTPUT_SIZE, dg);
    int n = snprintf(text, sizeof(text), "%s %llu %s\n", op,
                     (unsigned long long)m->seq, dg);
    if (n <= 0 || (size_t)n >= sizeof(text)) {
        fe_why(why, FLEET_ENROL_WHY_ARGUMENTS);
        return false;
    }
    return fe_replace_leaf(FLEET_HWM_LEAF, text, (size_t)n,
                           FLEET_ENROL_WHY_ROSTER_UNWRITABLE, changed, why);
}

/* NULL when the head read as `r` is the one the record vouches for;
 * otherwise the name of why it is not trusted. */
static const char *fe_head_vouched(
    const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES], const char *text,
    enum fe_read r, enum fe_hwm_state hs, const struct fe_hwm *m,
    struct fleet_head *out)
{
    uint8_t digest[SHA256_OUTPUT_SIZE];
    if (hs != FE_HWM_OK)
        return FLEET_ENROL_WHY_HEAD_HWM;
    if (memcmp(m->op, operator_pubkey, FLEET_ENROL_PUBKEY_BYTES) != 0)
        return FLEET_ENROL_WHY_HEAD_HWM;
    if (r != FE_READ_OK)
        return FLEET_ENROL_WHY_HEAD_TORN;
    fe_head_digest(text, digest);
    if (memcmp(digest, m->digest, sizeof(digest)) != 0 ||
        !fleet_head_parse(text, out, NULL) || out->seq != m->seq ||
        memcmp(out->operator_pubkey, operator_pubkey,
               FLEET_ENROL_PUBKEY_BYTES) != 0)
        return FLEET_ENROL_WHY_HEAD_TORN;
    return NULL;
}

static enum fleet_head_state fe_head_load_mode(
    const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
    struct fleet_head *out, const char **why, bool readonly)
{
    char *text = zcl_malloc(FLEET_ENROL_HEAD_TEXT_MAX + 4u, "fleet-head");
    const char *bad;
    struct fe_hwm m;
    size_t len = 0;
    enum fe_read r;
    enum fe_hwm_state hs;
    fe_why(why, NULL);
    memset(out, 0, sizeof(*out));
    if (!text) {
        fe_why(why, FLEET_ENROL_WHY_HEAD_UNREADABLE);
        return FLEET_HEAD_BAD;
    }
    r = fe_read_strict_mode(FLEET_HEAD_LEAF, text, FLEET_ENROL_HEAD_TEXT_MAX + 4u,
                            &len, readonly);
    hs = fe_hwm_read_mode(&m, readonly);
    if (r == FE_READ_ABSENT && hs == FE_HWM_ABSENT) {
        free(text);
        return FLEET_HEAD_ABSENT;
    }
    while (r == FE_READ_OK && len > 0 &&
           (text[len - 1] == '\n' || text[len - 1] == '\r'))
        text[--len] = '\0';
    bad = fe_head_vouched(operator_pubkey, text, r, hs, &m, out);
    free(text);
    if (bad) {
        memset(out, 0, sizeof(*out));
        fe_why(why, bad);
        LOG_WARN(FLEET_DOMAIN,
                 "%s: the roster head or its sequence record is missing, "
                 "corrupt, torn, or not sealed by this fleet's operator key; "
                 "failing closed", bad);
        return FLEET_HEAD_BAD;
    }
    return FLEET_HEAD_OK;
}

static bool fe_head_same(const struct fleet_head *a, const struct fleet_head *b)
{
    return a->seq == b->seq && a->issued_at == b->issued_at &&
           a->n_revoked == b->n_revoked &&
           memcmp(a->operator_pubkey, b->operator_pubkey,
                  FLEET_ENROL_PUBKEY_BYTES) == 0 &&
           memcmp(a->revoked, b->revoked,
                  (size_t)a->n_revoked * FLEET_ENROL_PUBKEY_BYTES) == 0 &&
           memcmp(a->signature, b->signature, FLEET_ENROL_SIG_BYTES) == 0;
}

static bool fe_head_stale(const struct fleet_head *fresh, uint64_t bar,
                          const char **why)
{
    fe_why(why, FLEET_ENROL_WHY_HEAD_STALE);
    LOG_WARN(FLEET_DOMAIN, "fleet_head_stale: held seq=%llu, offered "
             "seq=%llu", (unsigned long long)bar,
             (unsigned long long)fresh->seq);
    return false;
}

/* The held head is trusted: compare against it. */
static bool fe_head_rule_held(const struct fleet_head *fresh,
                              const struct fleet_head *held, bool *store,
                              const char **why)
{
    if (fresh->seq < held->seq)
        return fe_head_stale(fresh, held->seq, why);
    if (fresh->seq > held->seq)
        return true;
    *store = false;
    if (fe_head_same(fresh, held))
        return true;
    fe_why(why, FLEET_ENROL_WHY_HEAD_CONFLICT);
    LOG_WARN(FLEET_DOMAIN, "fleet_head_conflict: two different heads "
             "carry the same sequence");
    return false;
}

/* What the stored head says about the sequence floor. A head that parses
 * and is sealed by the trusted operator is self-authenticating, so it floors
 * the sequence even when the record has been lowered or damaged. NONE is a
 * head that is absent or not such a head; UNASSESSABLE (allocation or read
 * failure) must never be read as NONE. */
enum fe_floor_state { FE_FLOOR_NONE = 0, FE_FLOOR_OK, FE_FLOOR_UNASSESSABLE };

#ifdef ZCL_TESTING
bool fleet_enrol_test_fail_floor = false;
#endif

static enum fe_floor_state fe_stored_head_floor(
    const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES], uint64_t *floor)
{
    char *text = zcl_malloc(FLEET_ENROL_HEAD_TEXT_MAX + 4u, "fleet-head-floor");
    struct fleet_head *head = zcl_malloc(sizeof(*head), "fleet-head-floor");
    enum fe_floor_state state = FE_FLOOR_UNASSESSABLE;
    enum fe_read r = FE_READ_BAD;
    size_t len = 0;
    *floor = 0;
#ifdef ZCL_TESTING
    if (fleet_enrol_test_fail_floor) {
        free(text);
        free(head);
        return FE_FLOOR_UNASSESSABLE;
    }
#endif
    if (text && head)
        r = fe_read_strict(FLEET_HEAD_LEAF, text,
                           FLEET_ENROL_HEAD_TEXT_MAX + 4u, &len);
    if (text && head && r == FE_READ_ABSENT)
        state = FE_FLOOR_NONE;
    if (text && head && r == FE_READ_OK) {
        while (len > 0 && (text[len - 1] == '\n' || text[len - 1] == '\r'))
            text[--len] = '\0';
        state = FE_FLOOR_NONE;
        if (fleet_head_parse(text, head, NULL) &&
            memcmp(head->operator_pubkey, operator_pubkey,
                   FLEET_ENROL_PUBKEY_BYTES) == 0) {
            *floor = head->seq;
            state = FE_FLOOR_OK;
        }
    }
    free(text);
    free(head);
    return state;
}

/* TORN: the floor is the higher of the record and any intact signed head on
 * disk. Only the head the record vouches for (same digest, not below the
 * floor) or a sequence ABOVE the floor repairs it. */
static bool fe_head_rule_torn(const struct fleet_head *fresh,
                              const char *line, const struct fe_hwm *m,
                              uint64_t stored_floor, const char **why)
{
    uint8_t digest[SHA256_OUTPUT_SIZE];
    uint64_t floor = m->seq > stored_floor ? m->seq : stored_floor;
    fe_head_digest(line, digest);
    if (fresh->seq > floor ||
        (fresh->seq == floor && memcmp(digest, m->digest, sizeof(digest)) == 0))
        return true;
    if (fresh->seq < floor)
        return fe_head_stale(fresh, floor, why);
    fe_why(why, FLEET_ENROL_WHY_HEAD_CONFLICT);
    LOG_WARN(FLEET_DOMAIN, "fleet_head_conflict: the offered head is not the "
             "one the sequence record vouches for");
    return false;
}

/* TORN, with the stored head's floor assessed first: a floor that cannot be
 * assessed refuses the import rather than reading as "no stored head". */
static bool fe_head_rule_torn_checked(
    const struct fleet_head *fresh, const char *line, const struct fe_hwm *m,
    const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES], const char **why)
{
    uint64_t floor = 0;
    if (fe_stored_head_floor(operator_pubkey, &floor) ==
        FE_FLOOR_UNASSESSABLE) {
        fe_why(why, FLEET_ENROL_WHY_HEAD_UNREADABLE);
        LOG_WARN(FLEET_DOMAIN, "fleet_head_unreadable: the stored head's "
                 "sequence could not be assessed; refusing the import");
        return false;
    }
    return fe_head_rule_torn(fresh, line, m, floor, why);
}

/* The sequence rule. `store` says the new head must be written. Only a box
 * with neither file is fresh; a record naming another operator, or a head
 * without a readable record, refuses every import (owner repair). */
static bool fe_head_rule(const struct fleet_head *fresh, const char *line,
                         const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                         bool *store, const char **why)
{
    struct fleet_head *held = zcl_malloc(sizeof(*held), "fleet-head-held");
    const char *lwhy = NULL;
    struct fe_hwm m;
    enum fleet_head_state state;
    bool ok = false;
    *store = true;
    if (!held) {
        fe_why(why, FLEET_ENROL_WHY_HEAD_UNREADABLE);
        return false;
    }
    state = fleet_head_load(operator_pubkey, held, &lwhy);
    (void)fe_hwm_read(&m);
    if (state == FLEET_HEAD_OK)
        ok = fe_head_rule_held(fresh, held, store, why);
    else if (state == FLEET_HEAD_BAD && lwhy &&
             strcmp(lwhy, FLEET_ENROL_WHY_HEAD_TORN) == 0)
        ok = fe_head_rule_torn_checked(fresh, line, &m, operator_pubkey, why);
    else if (state == FLEET_HEAD_BAD)
        fe_why(why, lwhy ? lwhy : FLEET_ENROL_WHY_HEAD_HWM);
    else
        ok = true; /* neither file: a fresh box */
    free(held);
    return ok;
}

#ifdef ZCL_TESTING
bool fleet_enrol_test_crash_before_head = false;
static bool fe_test_crash(void) { return fleet_enrol_test_crash_before_head; }
#else
static bool fe_test_crash(void) { return false; }
#endif

/* Pin, then the record for the new head, then the head. Anything changed
 * before a later step fails is reported as the named partial state. */
static bool fe_head_commit(const char *line, const struct fleet_head *head,
                           bool pin, bool store, bool *replaced,
                           const char **why)
{
    struct fe_hwm m;
    bool changed = false;
    bool ok = !pin || fe_pin_write(head->operator_pubkey, &changed, why);
    if (ok && store) {
        memcpy(m.op, head->operator_pubkey, sizeof(m.op));
        m.seq = head->seq;
        fe_head_digest(line, m.digest);
        ok = fe_hwm_write(&m, &changed, why);
        if (ok && fe_test_crash()) {
            fe_why(why, FLEET_ENROL_WHY_ROSTER_UNWRITABLE);
            ok = false;
        }
        ok = ok && fe_replace_leaf(FLEET_HEAD_LEAF, line, strlen(line),
                                   FLEET_ENROL_WHY_ROSTER_UNWRITABLE, &changed,
                                   why);
        *replaced = ok;
    }
    if (!ok && changed)
        fe_why(why, FLEET_ENROL_WHY_IMPORT_PARTIAL);
    return ok;
}

static bool fe_head_import_locked(const char *line,
                       const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                       bool confirm_operator_change, struct fleet_head *out,
                       bool *replaced, const char **why)
{
    bool store = false, pin = false;
    fe_why(why, NULL);
    *replaced = false;
    if (!line || !operator_pubkey || !fleet_head_is_line(line) ||
        strlen(line) >= (size_t)FLEET_ENROL_HEAD_TEXT_MAX) {
        fe_why(why, FLEET_ENROL_WHY_ARGUMENTS);
        return false;
    }
    if (!fleet_head_parse(line, out, NULL)) {
        fe_why(why, FLEET_ENROL_WHY_ROSTER_LINE_UNSEALED);
        return false;
    }
    /* Sealed by itself is not enough: it must be sealed by the key this box
     * trusts. Another operator's head is a changed fleet root, whatever the
     * pin says; this box is never told to trust it by a head it was given. */
    if (memcmp(out->operator_pubkey, operator_pubkey,
               FLEET_ENROL_PUBKEY_BYTES) != 0) {
        fe_why(why, FLEET_ENROL_WHY_ROOT_CHANGED);
        LOG_WARN(FLEET_DOMAIN, "fleet_root_changed: this head is sealed by "
                 "an operator key other than the one this box trusts");
        return false;
    }
    if (!fe_pin_gate(out->operator_pubkey, confirm_operator_change, &pin, why, false) ||
        !fe_head_rule(out, line, operator_pubkey, &store, why))
        return false;
    fe_test_after_check();
    return fe_head_commit(line, out, pin, store, replaced, why);
}

bool fleet_head_import(const char *line,
                       const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                       bool confirm_operator_change, struct fleet_head *out,
                       bool *replaced, const char **why)
{
    struct fe_state_lock lock;
    bool ok;
    *replaced = false;
    if (!fe_state_lock_take(&lock, why))
        return false;
    ok = fe_head_import_locked(line, operator_pubkey, confirm_operator_change,
                               out, replaced, why);
    fe_state_unlock(&lock);
    return ok;
}

/* A machine row must not be imported for a box the live head revokes, and
 * must not be imported past a head this box cannot trust. */
enum fleet_head_state fleet_head_load(
    const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
    struct fleet_head *out, const char **why)
{ return fe_head_load_mode(operator_pubkey, out, why, false); }

enum fleet_head_state fleet_head_load_existing(
    const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
    struct fleet_head *out, const char **why)
{ return fe_head_load_mode(operator_pubkey, out, why, true); }

static bool fe_row_head_gate(
    const struct fleet_machine *row,
    const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES], const char **why,
    bool readonly)
{
    struct fleet_head *head = zcl_malloc(sizeof(*head), "fleet-head-gate");
    enum fleet_head_state state;
    bool revoked;
    if (!head) {
        fe_why(why, FLEET_ENROL_WHY_HEAD_UNREADABLE);
        return false;
    }
    state = fe_head_load_mode(operator_pubkey, head, why, readonly);
    revoked = state == FLEET_HEAD_OK &&
              (fleet_head_revokes(head, row->receipt.box_pubkey) ||
               fleet_head_revokes(head, row->receipt.signer_pubkey));
    free(head);
    if (state == FLEET_HEAD_BAD)
        return false;
    if (revoked) {
        fe_why(why, FLEET_ENROL_WHY_BOX_REVOKED);
        LOG_WARN(FLEET_DOMAIN, "fleet_box_revoked: the roster head revokes "
                 "this box; its row is not imported");
        return false;
    }
    return true;
}

/* Record the pin after a row import; a failure after the row was appended or
 * the pin leaf moved is the named partial state. */
static bool fe_row_pin_finish(bool pin, bool appended,
                              const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                              const char **why)
{
    bool pin_changed = false;
    if (pin && !fe_pin_write(operator_pubkey, &pin_changed, why)) {
        if (appended || pin_changed)
            fe_why(why, FLEET_ENROL_WHY_IMPORT_PARTIAL);
        return false;
    }
    return true;
}

static bool fe_row_validate(const char *line,
                            const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                            bool confirm_operator_change, struct fleet_machine *out,
                            struct fleet_roster_scan *scan, bool *pin,
                            const char **why, bool readonly)
{
    fe_why(why, NULL);
    if (!line || !operator_pubkey || !out ||
        strlen(line) >= (size_t)FLEET_ENROL_MACHINE_TEXT_MAX) {
        fe_why(why, FLEET_ENROL_WHY_ARGUMENTS);
        return false;
    }
    if (!fleet_machine_parse(line, operator_pubkey, out, NULL)) {
        fe_why(why, FLEET_ENROL_WHY_ROSTER_LINE_UNSEALED);
        return false;
    }
    if (!fe_pin_gate(operator_pubkey, confirm_operator_change, pin, why, readonly) ||
        !fe_row_head_gate(out, operator_pubkey, why, readonly) ||
        !fe_roster_query(operator_pubkey, out->receipt.invite.name,
                         out->receipt.box_pubkey, NULL, NULL, scan, why, readonly))
        return false;
    if (scan->name_taken && !scan->same_box) {
        fe_why(why, FLEET_ENROL_WHY_NAME_TAKEN);
        return false;
    }
    return true;
}

bool fleet_roster_preview(const char *line,
                          const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                          struct fleet_machine *out, const char **why)
{
    struct fleet_roster_scan scan = {0};
    bool pin = false;
    return fe_row_validate(line, operator_pubkey, false, out, &scan, &pin, why, true);
}

static bool fe_row_import_locked(const char *line,
                                const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                                bool confirm_operator_change,
                                struct fleet_machine *out, bool *appended,
                                const char **why)
{
    struct fleet_roster_scan scan = {0};
    bool pin = false;
    *appended = false;
    if (!fe_row_validate(line, operator_pubkey, confirm_operator_change, out,
                         &scan, &pin, why, false))
        return false;
    if (!scan.same_box) {
        if (!fleet_roster_append(line, why))
            return false;
        *appended = true;
    }
    /* already held: importing twice adds nothing, but it is still an import
     * from this operator, so the pin is recorded all the same. */
    return fe_row_pin_finish(pin, *appended, operator_pubkey, why);
}

bool fleet_roster_import_pinned(const char *line,
                                const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                                bool confirm_operator_change,
                                struct fleet_machine *out, bool *appended,
                                const char **why)
{
    struct fe_state_lock lock;
    bool ok;
    *appended = false;
    if (!fe_state_lock_take(&lock, why))
        return false;
    ok = fe_row_import_locked(line, operator_pubkey, confirm_operator_change,
                              out, appended, why);
    fe_state_unlock(&lock);
    return ok;
}

bool fleet_roster_import(const char *line,
                         const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                         struct fleet_machine *out, bool *appended,
                         const char **why)
{
    return fleet_roster_import_pinned(line, operator_pubkey, false, out,
                                      appended, why);
}

/* ── the signers bound to a box ───────────────────────────────────────────
 * The relay gate sees a peer's board SIGNING key, not its box key, so a head
 * that revokes a box must also name every signer the operator's own roster
 * rows have ever bound to that box (a rotation leaves more than one). */

struct fe_signer_hunt {
    const uint8_t *box;
    uint8_t (*signers)[FLEET_ENROL_PUBKEY_BYTES];
    size_t cap;
    size_t n;
    bool found;
    bool overflow;
};

static void fe_signer_visit(const struct fleet_machine *machine, void *user)
{
    static const uint8_t none[FLEET_ENROL_PUBKEY_BYTES];
    struct fe_signer_hunt *hunt = user;
    if (memcmp(machine->receipt.box_pubkey, hunt->box,
               FLEET_ENROL_PUBKEY_BYTES) != 0)
        return;
    hunt->found = true;
    if (memcmp(machine->receipt.signer_pubkey, none, sizeof(none)) == 0)
        return;
    for (size_t i = 0; i < hunt->n; ++i)
        if (memcmp(hunt->signers[i], machine->receipt.signer_pubkey,
                   FLEET_ENROL_PUBKEY_BYTES) == 0)
            return;
    if (hunt->n >= hunt->cap) {
        hunt->overflow = true;
        return;
    }
    memcpy(hunt->signers[hunt->n++], machine->receipt.signer_pubkey,
           FLEET_ENROL_PUBKEY_BYTES);
}

bool fleet_roster_signers_of_box(
    const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
    const uint8_t box_pubkey[FLEET_ENROL_PUBKEY_BYTES],
    uint8_t (*signers)[FLEET_ENROL_PUBKEY_BYTES], size_t cap, size_t *count,
    bool *found, const char **why)
{
    struct fe_signer_hunt hunt = { .box = box_pubkey, .signers = signers,
                                   .cap = cap };
    struct fleet_roster_scan scan = {0};
    *found = false;
    *count = 0;
    if (!fleet_roster_each(operator_pubkey, fe_signer_visit, &hunt, &scan,
                           why))
        return false;
    if (hunt.overflow) {
        fe_why(why, FLEET_ENROL_WHY_HEAD_TOO_LARGE);
        return false;
    }
    *found = hunt.found;
    *count = hunt.n;
    return true;
}

/* ── spent invite nonces ────────────────────────────────────────────────── */

struct fe_nonce_hunt {
    const char *hex;
    bool seen;
};

static void fe_nonce_line(char *line, void *user)
{
    struct fe_nonce_hunt *hunt = user;
    if (strcmp(line, hunt->hex) == 0) hunt->seen = true;
}

bool fleet_nonce_seen(const uint8_t nonce[FLEET_ENROL_NONCE_BYTES], bool *seen,
                      const char **why)
{
    char *text = zcl_malloc(FLEET_NONCE_MAX_BYTES + 1u, "fleet-invite-nonces");
    char hex[FLEET_ENROL_NONCE_HEX];
    struct fe_nonce_hunt hunt = { hex, false };
    size_t len = 0;
    fe_why(why, NULL);
    *seen = false;
    zcl_hex_encode(nonce, FLEET_ENROL_NONCE_BYTES, hex);
    if (!text) {
        fe_why(why, FLEET_ENROL_WHY_ROSTER_UNREADABLE);
        return false;
    }
    if (!fe_slurp(FLEET_NONCE_LEAF, text, FLEET_NONCE_MAX_BYTES + 1u, &len,
                  why)) {
        free(text);
        return false;
    }
    fe_each_line(text, fe_nonce_line, &hunt);
    free(text);
    *seen = hunt.seen;
    return true;
}

bool fleet_nonce_spend(const uint8_t nonce[FLEET_ENROL_NONCE_BYTES],
                       const char **why)
{
    char hex[FLEET_ENROL_NONCE_HEX];
    fe_why(why, NULL);
    zcl_hex_encode(nonce, FLEET_ENROL_NONCE_BYTES, hex);
    return fe_append_line(FLEET_NONCE_LEAF, hex,
                          FLEET_ENROL_WHY_ROSTER_UNWRITABLE, why);
}

/* ── rendering ──────────────────────────────────────────────────────────── */

void fleet_machine_render(const struct fleet_machine *machine,
                          struct json_value *out)
{
    char fingerprint[FLEET_ENROL_PUBKEY_HEX];
    struct json_value verified, self_reported;
    zcl_hex_encode(machine->receipt.box_pubkey, FLEET_ENROL_PUBKEY_BYTES,
                   fingerprint);
    json_init(&verified);
    json_set_object(&verified);
    /* What the operator signature actually attests: the operator decided
     * this name, this key, this port, at this time. */
    (void)json_push_kv_str(&verified, "name", machine->receipt.invite.name);
    (void)json_push_kv_str(&verified, "box_pubkey", fingerprint);
    (void)json_push_kv_int(&verified, "enrolled_at", machine->enrolled_at);
    (void)json_push_kv_int(&verified, "relay_port", machine->relay_port);
    (void)json_push_kv_bool(&verified, "bridge_key_present",
                            machine->receipt.ssh_pubkey[0] != '\0');

    json_init(&self_reported);
    json_set_object(&self_reported);
    /* What the BOX said about itself. Signed by the box, measured by
     * nobody. Kept in its own object so no reader can mistake one for the
     * other by reading a flat row. */
    /* The locator sits beside the name — first in this object, so a reader
     * scanning `fleet machines` finds "who" and "where" together. It stays
     * on the self_reported side because the box asserted it and nobody has
     * dialled it; moving it under `verified` would be a lie about what the
     * operator signature covers. */
    (void)json_push_kv_str(&self_reported, "onion", machine->receipt.onion);
    (void)json_push_kv_str(&self_reported, "hostname",
                           machine->receipt.facts.hostname);
    (void)json_push_kv_str(&self_reported, "os", machine->receipt.facts.os);
    (void)json_push_kv_str(&self_reported, "os_version",
                           machine->receipt.facts.os_version);
    (void)json_push_kv_str(&self_reported, "arch", machine->receipt.facts.arch);
    (void)json_push_kv_int(&self_reported, "cores",
                           (int64_t)machine->receipt.facts.cores);
    (void)json_push_kv_int(&self_reported, "ram_mb",
                           (int64_t)machine->receipt.facts.ram_mb);
    (void)json_push_kv_int(&self_reported, "disk_free_mb",
                           (int64_t)machine->receipt.facts.disk_free_mb);
    (void)json_push_kv_str(&self_reported, "toolchain",
                           machine->receipt.facts.toolchain);
    (void)json_push_kv_str(&self_reported, "git_head",
                           machine->receipt.facts.git_head);

    json_set_object(out);
    (void)json_push_kv(out, "verified", &verified);
    (void)json_push_kv(out, "self_reported", &self_reported);
    json_free(&verified);
    json_free(&self_reported);
}

/* ── the ssh bridge ─────────────────────────────────────────────────────── */

bool fleet_bridge_line(const char *ssh_pubkey, uint16_t port, const char *name,
                       char *out, size_t cap)
{
    int n;
    if (!ssh_pubkey || !ssh_pubkey[0] || !fleet_enrol_name_valid(name) ||
        port < FLEET_ENROL_PORT_FIRST || port > FLEET_ENROL_PORT_LAST)
        return false;
    /* `restrict` denies everything sshd knows how to deny — no shell, no
     * command, no agent forwarding, no X11, no pty, no user rc — and is
     * FORWARD-COMPATIBLE: a future sshd restriction is denied by default
     * rather than silently permitted. The single re-grant is one loopback
     * listen port, so the key cannot forward to anything else, cannot
     * listen on a public address, and cannot run anything. */
    n = snprintf(out, cap,
                 "restrict,port-forwarding,permitlisten=\"127.0.0.1:%u\" %s "
                 "z23-fleet-%s",
                 (unsigned)port, ssh_pubkey, name);
    return n > 0 && (size_t)n < cap;
}

/* Is a line for this box already present? The match is on the comment tag
 * alone, so re-admitting a box whose port or key changed replaces nothing
 * and adds nothing — the operator is told the tag is already there and
 * decides. Silently rewriting an authorized_keys line the owner may have
 * edited is not this command's business. */
static bool fe_bridge_present(const char *body, const char *name)
{
    char tag[FLEET_ENROL_NAME_MAX + 16];
    if (snprintf(tag, sizeof(tag), "z23-fleet-%s", name) <= 0) return false;
    return strstr(body, tag) != NULL;
}

/* Read the measured store before any string search or append. */
static bool fe_bridge_read(struct platform_private_file *file, char **body,
                           uint64_t *size)
{
    *body = NULL;
    *size = 0;
    if (!platform_private_file_size(file, size) ||
        *size >= FLEET_BRIDGE_MAX_BYTES) return false;
    *body = zcl_malloc((size_t)*size + 1u, "fleet-authorized-keys");
    if (!*body) return false;
    if (!platform_private_file_read_at(file, *body, (size_t)*size, 0))
        return false;
    if (memchr(*body, '\0', (size_t)*size)) return false;
    (*body)[(size_t)*size] = '\0';
    return true;
}

bool fleet_bridge_authorize(const char *line, const char *name, bool *added,
                            const char **why)
{
    struct platform_private_file file;
    char *body = NULL;
    char path[FLEET_ENROL_PATH_MAX];
    char buffer[FLEET_ENROL_SSH_MAX + 256];
    const char *home = NULL;
    uint64_t size = 0;
    int n;
    fe_why(why, NULL);
    *added = false;
#if defined(_WIN32)
    home = getenv("USERPROFILE");
#else
    home = getenv("HOME");
#endif
    if (!home || !home[0] || !fleet_enrol_name_valid(name)) {
        fe_why(why, FLEET_ENROL_WHY_BRIDGE_UNWRITABLE);
        return false;
    }
    n = snprintf(path, sizeof(path), "%s/.ssh/authorized_keys", home);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        fe_why(why, FLEET_ENROL_WHY_BRIDGE_UNWRITABLE);
        return false;
    }
    n = snprintf(buffer, sizeof(buffer), "%s\n", line);
    if (n <= 0 || (size_t)n >= sizeof(buffer)) {
        fe_why(why, FLEET_ENROL_WHY_ARGUMENTS);
        return false;
    }
    platform_private_file_init(&file);
    /* ~/.ssh must already exist with the mode sshd insists on. Creating it
     * here would mean guessing an owner's ssh layout from a fleet command;
     * refusing by name is the honest answer. */
    if (!platform_private_file_open_locked_create_wait(path, &file)) {
        fe_why(why, FLEET_ENROL_WHY_BRIDGE_UNWRITABLE);
        LOG_WARN(FLEET_DOMAIN,
                 "cannot open the operator authorized_keys file; the bridge "
                 "needs ~/.ssh to exist already");
        return false;
    }
    bool ok = fe_bridge_read(&file, &body, &size);
    if (ok) {
        if (fe_bridge_present(body, name)) {
            platform_private_file_close(&file);
            free(body);
            return true; /* already granted; adding a second is a widening */
        }
        ok = platform_private_file_write_at(&file, buffer, (size_t)n, size) &&
             platform_private_file_authority_flush(&file);
    }
    platform_private_file_close(&file);
    free(body);
    if (!ok) {
        fe_why(why, FLEET_ENROL_WHY_BRIDGE_UNWRITABLE);
        LOG_WARN(FLEET_DOMAIN, "cannot append the restricted bridge line");
        return false;
    }
    *added = true;
    return true;
}
