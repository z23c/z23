/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: One-paste fleet enrolment — signed invite token, signed box
 *          enrolment receipt, and the operator-signed machine roster.
 *
 * THE PROBLEM. An owner with several computers had no way to add one to the
 * fleet except the manual `ops mesh pair plan` / `ops mesh pair commit`
 * ceremony: compare a Noise fingerprint out of band, on a box that already
 * runs a node and already holds a zcode-DHT delegation. A computer that has
 * only just cloned and built has none of that, so there was no first step.
 *
 * THE SHAPE. Three artefacts, one identity, no new key type:
 *
 *   invite   `z23 fleet invite --name=<box>` mints one base64url token that
 *            names the box, an expiry, a random nonce and an optional relay
 *            endpoint, signed by THIS box's Ed25519 key. Nothing private is
 *            in it. A leaked token can enrol one box under that name, once,
 *            before it expires.
 *
 *   receipt  `z23 fleet join <token>` on the new computer verifies the token
 *            against the operator public key the token carries — trust on
 *            paste: the owner carried that key here — records it as the
 *            fleet operator, creates this box's own Ed25519 key, collects
 *            what it can honestly say about itself, and signs a receipt
 *            binding {invite, facts, box public key, ssh public key}.
 *
 *   machine  `z23 fleet admit <receipt>` on the manager re-checks that the
 *            invite was minted by THIS box, that the nonce has never been
 *            spent, that the name is free, and that the box signed its own
 *            facts; then it appends ONE operator-signed roster line and, as
 *            a BRIDGE only, one restricted `authorized_keys` line.
 *
 * WHY NO NETWORK CALL. The receipt is carried by the same operator who
 * carried the invite. That needs no reachable relay, no open port, no TLS
 * trust decision and no NAT traversal, and it works on the box's first
 * minute of life, when no node runs on either end. The signatures are the
 * whole trust root either way; a transport would only move the bytes.
 * `fleet join` therefore emits a typed `next_step` naming the native mesh
 * pairing that follows once the box has a node and a delegation.
 *
 * THE NAME IS THE HANDLE. Every machine carries one required, unique,
 * human-readable name, chosen by the owner at `fleet invite --name=` and
 * bound into the invite the box signs back. It is what every leaf prints
 * first and what every refusal says, because it is how the owner and their
 * agents TALK about a machine. A machine's onion address, Noise
 * fingerprint and ZID are a different kind of thing: they are OBSERVED,
 * they rotate, and none of them is ever the display name.
 *
 * The receipt carries ONE of those columns today: an optional `onion`, the
 * persistent onion hostname the joining box says it will be reachable at.
 * It is beside the name, never instead of it, and it is SELF-REPORTED — the
 * box signed the string, so it is authenticated, but no peer has dialled it
 * and `fleet machines` renders it in the self_reported object for exactly
 * that reason. A later unit that actually dials the address and gets the
 * box's key back is what would make it verified; until then a reader that
 * treats this field as proof of reachability is reading it wrong. It exists
 * now so that unit, and the NAT-traversal work behind it, has a signed
 * place to look the address up instead of inventing a second registry.
 *
 * The name is bound inside the box's own signature over the receipt, which
 * is what makes "this box, under this name" one statement rather than two.
 * The cost of that is that renaming is not an edit: the operator cannot
 * re-sign a box's receipt. A rename needs its own operator-signed record
 * kind and a resolution rule in the reader; it is deliberately not part of
 * this record set.
 *
 * WHAT IS AND IS NOT ATTESTED. The operator signature on a roster line
 * attests the NAME, the box public key, the relay port and the enrolment
 * time — the operator decided those. Everything the box says about its own
 * hardware and toolchain is self-reported: authenticated (the box signed
 * it) but not verified (nobody else measured it). `fleet machines` keeps
 * the two in separate arrays and never merges them.
 *
 * IDENTITY. One Ed25519 key per box, at platform_state_root()/fleet/
 * box.ed25519, mode 0600, created on first use — the same custody shape as
 * tools/dev/dev_proof_signer.h, deliberately a SIBLING of it rather than
 * the same file: a push-proof signer and a fleet operator are different
 * authorities and must be revocable apart. Manager and box run the same
 * code with the same key file; which role a box plays is decided by which
 * verb the owner runs on it, not by a second key type.
 */

#ifndef ZCL_TOOLS_DEV_FLEET_ENROL_H
#define ZCL_TOOLS_DEV_FLEET_ENROL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    FLEET_ENROL_PUBKEY_BYTES = 32,
    FLEET_ENROL_SIG_BYTES = 64,
    FLEET_ENROL_SEED_BYTES = 32,
    FLEET_ENROL_NONCE_BYTES = 16,
    FLEET_ENROL_PUBKEY_HEX = 65,   /* 64 hex digits + NUL */
    FLEET_ENROL_NONCE_HEX = 33,
    /* The human name. Every leaf prints it first and every refusal names
     * it, because it is how the owner and their agents TALK about a
     * machine. Two to twenty-four characters so it fits a sentence and a
     * terminal column; one spelling per name so two people saying
     * "workshop" mean one box. */
    FLEET_ENROL_NAME_MIN = 2,
    FLEET_ENROL_NAME_MAX = 24,
    FLEET_ENROL_RELAY_MAX = 64,
    /* A v3 onion hostname is 56 base32 characters plus ".onion" = 62. The
     * ceiling leaves room for an explicit ":port" and nothing more; it is
     * NOT a general host field. */
    FLEET_ENROL_ONION_MAX = 72,
    FLEET_ENROL_TEXT_MAX = 96,     /* hostname/os-version/toolchain fields */
    FLEET_ENROL_SSH_MAX = 512,
    FLEET_ENROL_PATH_MAX = 4096,
    /* Wire ceilings. Every decoder refuses more than these before it
     * allocates or copies anything, so a pasted blob can never be a length
     * argument to something larger than the buffer holding it. */
    FLEET_ENROL_INVITE_WIRE_MAX = 256,
    FLEET_ENROL_RECEIPT_WIRE_MAX = 1616,
    FLEET_ENROL_MACHINE_WIRE_MAX = 1744,
    /* base64url is 4 characters per 3 bytes; +8 covers the remainder and
     * the NUL with room to spare. */
    FLEET_ENROL_MACHINE_TEXT_MAX = (FLEET_ENROL_MACHINE_WIRE_MAX * 4) / 3 + 8,
    /* The closed relay port range the bridge assigns from. Closed because a
     * range an attacker can steer is a port-selection primitive, and because
     * a fleet that outgrows this many boxes should be told so by name. */
    FLEET_ENROL_PORT_FIRST = 22200,
    FLEET_ENROL_PORT_LAST = 22263,
    FLEET_ENROL_ROSTER_MAX = FLEET_ENROL_PORT_LAST - FLEET_ENROL_PORT_FIRST + 1,
    /* Invite lifetime bounds, in hours. An invite that never expires is a
     * standing credential; one that expires before the owner can paste it
     * is useless. */
    FLEET_ENROL_TTL_HOURS_MIN = 1,
    FLEET_ENROL_TTL_HOURS_MAX = 168,
    FLEET_ENROL_TTL_HOURS_DEFAULT = 24,
};

/* Typed refusals. These exact strings are what a leaf puts in its evidence
 * field, so an operator or a small model can act on the line without
 * reading this file. Nothing here is a diagnosis of the network. */
#define FLEET_ENROL_WHY_STATE_ROOT "fleet_state_root_unavailable"
#define FLEET_ENROL_WHY_KEY_UNWRITABLE "box_key_unwritable"
#define FLEET_ENROL_WHY_NAME_INVALID "invite_name_invalid"
#define FLEET_ENROL_WHY_TTL_INVALID "invite_ttl_invalid"
#define FLEET_ENROL_WHY_RELAY_INVALID "invite_relay_invalid"
#define FLEET_ENROL_WHY_INVITE_MALFORMED "invite_malformed"
#define FLEET_ENROL_WHY_INVITE_SIGNATURE "invite_signature_invalid"
#define FLEET_ENROL_WHY_INVITE_EXPIRED "invite_expired"
#define FLEET_ENROL_WHY_INVITE_NOT_OURS "invite_not_ours"
#define FLEET_ENROL_WHY_INVITE_REPLAYED "invite_replayed"
#define FLEET_ENROL_WHY_NAME_TAKEN "invite_name_taken"
#define FLEET_ENROL_WHY_ONION_INVALID "join_onion_invalid"
#define FLEET_ENROL_WHY_RECEIPT_MALFORMED "receipt_malformed"
#define FLEET_ENROL_WHY_BOX_SIGNATURE "box_signature_invalid"
#define FLEET_ENROL_WHY_ROSTER_UNREADABLE "roster_unreadable"
#define FLEET_ENROL_WHY_ROSTER_UNWRITABLE "roster_unwritable"
#define FLEET_ENROL_WHY_ROSTER_FULL "roster_full"
#define FLEET_ENROL_WHY_BRIDGE_UNWRITABLE "authorized_keys_unwritable"
#define FLEET_ENROL_WHY_ARGUMENTS "fleet_arguments_invalid"

/* ── the three records ──────────────────────────────────────────────────── */

struct fleet_invite {
    char name[FLEET_ENROL_NAME_MAX + 1];
    int64_t expires_unix;
    uint8_t nonce[FLEET_ENROL_NONCE_BYTES];
    /* Where the bridge lives, verbatim as the operator typed it. Empty when
     * the fleet has no relay yet; enrolment does not need one. */
    char relay[FLEET_ENROL_RELAY_MAX + 1];
    uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES];
    uint8_t signature[FLEET_ENROL_SIG_BYTES];
};

/* What a box says about itself. Every field is self-reported and the roster
 * renders it as such; none of it is measured by anybody else. */
struct fleet_box_facts {
    char hostname[FLEET_ENROL_TEXT_MAX + 1];
    char os[FLEET_ENROL_TEXT_MAX + 1];
    char os_version[FLEET_ENROL_TEXT_MAX + 1];
    char arch[FLEET_ENROL_TEXT_MAX + 1];
    /* The compiler that built this binary (__VERSION__), captured at
     * compile time. Not the toolchain capsule root: capturing that means
     * spawning the compiler, and an enrolment must not need a process
     * spawn capability to say what built it. */
    char toolchain[FLEET_ENROL_TEXT_MAX + 1];
    char git_head[FLEET_ENROL_TEXT_MAX + 1];
    uint32_t cores;
    uint64_t ram_mb;
    uint64_t disk_free_mb;
};

struct fleet_receipt {
    struct fleet_invite invite;
    /* The invite exactly as it arrived, so the manager re-verifies the
     * operator signature over the SAME bytes it minted rather than over a
     * re-encoding of a parse. */
    uint8_t invite_wire[FLEET_ENROL_INVITE_WIRE_MAX];
    size_t invite_wire_len;
    /* The persistent onion hostname this box says it answers on, or "" when
     * it has none yet. Self-reported: signed by the box, dialled by nobody.
     * Beside the name, never a substitute for it. */
    char onion[FLEET_ENROL_ONION_MAX + 1];
    struct fleet_box_facts facts;
    char ssh_pubkey[FLEET_ENROL_SSH_MAX + 1]; /* "" when the box has none */
    uint8_t box_pubkey[FLEET_ENROL_PUBKEY_BYTES];
    uint8_t signature[FLEET_ENROL_SIG_BYTES];
};

struct fleet_machine {
    struct fleet_receipt receipt;
    uint8_t receipt_wire[FLEET_ENROL_RECEIPT_WIRE_MAX];
    size_t receipt_wire_len;
    int64_t enrolled_at;
    uint16_t relay_port;
    uint8_t signature[FLEET_ENROL_SIG_BYTES];
};

/* ── codec (tools/dev/fleet_enrol_codec.c) ──────────────────────────────── */

/* Validate one fleet name: 2..24 bytes of [a-z0-9-] with the first and
 * last byte alphanumeric. Closed allowlist, never a denylist of the
 * separators that would break the `authorized_keys` comment and the roster
 * line the name reaches. */
bool fleet_enrol_name_valid(const char *name);

/* Validate one optional onion locator: empty (the box has none), or a v3
 * hostname — exactly 56 characters of [a-z2-7] then ".onion" — with an
 * optional ":<port>" of one to five decimal digits. Closed allowlist: a v2
 * address, an uppercase spelling, a bare hostname and an IP literal are all
 * refused, because this field is a persistent onion identity and nothing
 * else. Says nothing about whether the address answers. */
bool fleet_enrol_onion_valid(const char *onion);

/* Mint a signed invite. `seed`/`pubkey` are this box's key. `text` receives
 * the unpadded base64url token. Refuses by name; writes nothing on refusal. */
bool fleet_invite_mint(const char *name, int64_t ttl_hours, const char *relay,
                       const uint8_t seed[FLEET_ENROL_SEED_BYTES],
                       const uint8_t pubkey[FLEET_ENROL_PUBKEY_BYTES],
                       int64_t now_unix, char *text, size_t text_cap,
                       struct fleet_invite *out, const char **why);

/* Decode and VERIFY one invite token. The signature is checked against the
 * operator public key the token itself carries, which proves internal
 * consistency and nothing about whose key that is; deciding to trust it is
 * the caller's separate act. Expiry is NOT checked here — `now_unix` is a
 * different question and each caller names its own refusal. */
bool fleet_invite_parse(const char *text, struct fleet_invite *out,
                        uint8_t *wire, size_t wire_cap, size_t *wire_len,
                        const char **why);

/* Sign one enrolment receipt with the box key. `invite_wire` is the token
 * bytes `fleet_invite_parse` returned. `onion` may be NULL or "" and is
 * refused by name when it is neither empty nor a v3 locator. */
bool fleet_receipt_mint(const uint8_t *invite_wire, size_t invite_wire_len,
                        const char *onion,
                        const struct fleet_box_facts *facts,
                        const char *ssh_pubkey,
                        const uint8_t seed[FLEET_ENROL_SEED_BYTES],
                        const uint8_t pubkey[FLEET_ENROL_PUBKEY_BYTES],
                        char *text, size_t text_cap, const char **why);

/* Decode and VERIFY one receipt: the box signature over its own bytes AND
 * the operator signature on the invite it carries. Both must hold. */
bool fleet_receipt_parse(const char *text, struct fleet_receipt *out,
                         uint8_t *wire, size_t wire_cap, size_t *wire_len,
                         const char **why);

/* Seal one roster line: the receipt bytes plus the operator's decisions
 * (when, which port), signed by the operator key. */
bool fleet_machine_mint(const uint8_t *receipt_wire, size_t receipt_wire_len,
                        int64_t enrolled_at, uint16_t relay_port,
                        const uint8_t seed[FLEET_ENROL_SEED_BYTES],
                        const uint8_t pubkey[FLEET_ENROL_PUBKEY_BYTES],
                        char *text, size_t text_cap, const char **why);

/* Decode one roster line and verify it was sealed by `operator_pubkey`. A
 * line that fails is not this fleet's row and is counted, never rendered. */
bool fleet_machine_parse(const char *text,
                         const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                         struct fleet_machine *out, const char **why);

/* ── box identity (tools/dev/fleet_enrol_key.c) ─────────────────────────── */

/* Absolute path of one leaf inside platform_state_root()/fleet/, creating
 * the private directory. `leaf` is a compiled-in constant, never input. */
bool fleet_enrol_state_path(const char *leaf, char *out, size_t cap);

/* This box's Ed25519 key. `create` mints one on first use and announces it
 * with a typed log line; a creation is never silent. */
bool fleet_enrol_key_load(uint8_t seed[FLEET_ENROL_SEED_BYTES],
                          uint8_t pubkey[FLEET_ENROL_PUBKEY_BYTES],
                          bool create, bool *present, const char **why);

/* The operator public key THIS box has been told to trust, recorded by
 * `fleet join`. `present` is false on a box that has never joined — the
 * normal state of the manager itself, which trusts its own key. */
bool fleet_enrol_operator_read(uint8_t pubkey[FLEET_ENROL_PUBKEY_BYTES],
                               bool *present, const char **why);
bool fleet_enrol_operator_write(
    const uint8_t pubkey[FLEET_ENROL_PUBKEY_BYTES], const char **why);

/* ── box facts (tools/dev/fleet_enrol_facts.c) ──────────────────────────── */

/* Collect what this box can honestly say about itself. Never fails: a fact
 * this host will not disclose is left empty or zero, because an enrolment
 * that refuses over an unreadable meminfo helps nobody. */
void fleet_enrol_facts_collect(struct fleet_box_facts *out);

/* This box's dedicated fleet ssh public key line (~/.ssh/z23_fleet.pub),
 * or "" when there is none. Dedicated by design: the bridge line restricts
 * exactly this key to one forwarded port, so it must not be a key the owner
 * also uses for shell access. */
void fleet_enrol_ssh_pubkey(char *out, size_t cap);

/* ── roster (tools/dev/fleet_enrol_store.c) ─────────────────────────────── */

struct fleet_roster_scan {
    uint32_t rows;             /* verified rows read */
    uint32_t unverifiable;     /* rows this operator key did not seal */
    bool name_taken;           /* the scanned name belongs to another box */
    bool same_box;             /* this exact box public key already enrolled */
    uint16_t existing_port;    /* its port, when same_box */
    uint16_t next_port;        /* lowest free port, 0 when the range is full */
};

/* Read the roster once, answering every admission question in one pass. */
bool fleet_roster_scan(const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                       const char *name,
                       const uint8_t box_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                       struct fleet_roster_scan *out, const char **why);

/* Append one sealed roster line. */
bool fleet_roster_append(const char *line, const char **why);

/* Has this invite nonce ever been spent on this box? Spending is a separate
 * call so a refusal later in admission cannot leave a nonce burned. */
bool fleet_nonce_seen(const uint8_t nonce[FLEET_ENROL_NONCE_BYTES], bool *seen,
                      const char **why);
bool fleet_nonce_spend(const uint8_t nonce[FLEET_ENROL_NONCE_BYTES],
                       const char **why);

/* Render one roster row into a caller-supplied JSON object. */
struct json_value;
void fleet_machine_render(const struct fleet_machine *machine,
                          struct json_value *out);

/* Walk verified roster rows oldest first, calling `visit` for each. Returns
 * false only when the roster cannot be read at all. */
bool fleet_roster_each(const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                       void (*visit)(const struct fleet_machine *, void *),
                       void *user, struct fleet_roster_scan *out,
                       const char **why);

/* ── the ssh bridge (tools/dev/fleet_enrol_store.c) ─────────────────────── */

/* Build the one line the bridge adds, exactly:
 *   restrict,port-forwarding,permitlisten="127.0.0.1:<port>" <key> z23-fleet-<name>
 * `restrict` denies everything sshd can deny — no shell, no agent
 * forwarding, no X11, no pty, no user rc — and the single re-grant is one
 * loopback listen port. Returns false when the pieces do not fit. */
bool fleet_bridge_line(const char *ssh_pubkey, uint16_t port, const char *name,
                       char *out, size_t cap);

/* Append `line` to the operator's ~/.ssh/authorized_keys, once. `added` is
 * false when a line carrying the same `z23-fleet-<name>` comment is already
 * there, which makes re-admitting the same box a no-op rather than a
 * second grant. Refuses when HOME is unset or the file cannot be written. */
bool fleet_bridge_authorize(const char *line, const char *name, bool *added,
                            const char **why);

#endif /* ZCL_TOOLS_DEV_FLEET_ENROL_H */
