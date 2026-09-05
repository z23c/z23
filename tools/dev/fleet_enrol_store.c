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
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLEET_DOMAIN "fleet-enrol"
#define FLEET_ROSTER_LEAF "machines.roster"
#define FLEET_NONCE_LEAF "invites.spent"

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
static bool fe_slurp(const char *leaf, char *buf, size_t cap, size_t *len,
                     const char **why)
{
    struct platform_positioned_file file;
    char path[FLEET_ENROL_PATH_MAX];
    uint64_t size = 0;
    *len = 0;
    buf[0] = '\0';
    if (!fleet_enrol_state_path(leaf, path, sizeof(path))) {
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

static bool fe_roster_walk(struct fe_walk *w, const char **why)
{
    char *text = zcl_malloc(FLEET_ROSTER_MAX_BYTES + 1u, "fleet-roster");
    size_t len = 0;
    memset(w->scan, 0, sizeof(*w->scan));
    memset(w->used, 0, sizeof(w->used));
    if (!text) {
        fe_why(why, FLEET_ENROL_WHY_ROSTER_UNREADABLE);
        return false;
    }
    if (!fe_slurp(FLEET_ROSTER_LEAF, text, FLEET_ROSTER_MAX_BYTES + 1u, &len,
                  why)) {
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

bool fleet_roster_scan(const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                       const char *name,
                       const uint8_t box_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                       struct fleet_roster_scan *out, const char **why)
{
    struct fe_walk w = {0};
    w.operator_pubkey = operator_pubkey;
    w.name = name;
    w.box_pubkey = box_pubkey;
    w.scan = out;
    fe_why(why, NULL);
    return fe_roster_walk(&w, why);
}

bool fleet_roster_each(const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                       void (*visit)(const struct fleet_machine *, void *),
                       void *user, struct fleet_roster_scan *out,
                       const char **why)
{
    struct fe_walk w = {0};
    w.operator_pubkey = operator_pubkey;
    w.scan = out;
    w.visit = visit;
    w.user = user;
    fe_why(why, NULL);
    return fe_roster_walk(&w, why);
}

bool fleet_roster_append(const char *line, const char **why)
{
    fe_why(why, NULL);
    return fe_append_line(FLEET_ROSTER_LEAF, line,
                          FLEET_ENROL_WHY_ROSTER_UNWRITABLE, why);
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
    bool ok = platform_private_file_size(&file, &size) &&
              size < FLEET_BRIDGE_MAX_BYTES;
    if (ok) {
        body = zcl_malloc((size_t)size + 1u, "fleet-authorized-keys");
        ok = body != NULL;
    }
    if (ok && size)
        ok = platform_private_file_read_at(&file, body, (size_t)size, 0);
    if (ok) {
        body[(size_t)size] = '\0';
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
