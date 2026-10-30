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
/* The host CSPRNG refused the one-time nonce. A minted invite whose nonce
 * is not random is a replayable invite, so this box declines to invent one
 * rather than hand the owner a token that admits exactly one machine. */
#define FLEET_ENROL_WHY_NONCE_UNAVAILABLE "invite_nonce_unavailable"
#define FLEET_ENROL_WHY_INVITE_MALFORMED "invite_malformed"
#define FLEET_ENROL_WHY_INVITE_SIGNATURE "invite_signature_invalid"
#define FLEET_ENROL_WHY_INVITE_EXPIRED "invite_expired"
#define FLEET_ENROL_WHY_INVITE_NOT_OURS "invite_not_ours"
#define FLEET_ENROL_WHY_INVITE_REPLAYED "invite_replayed"
#define FLEET_ENROL_WHY_NAME_TAKEN "invite_name_taken"
#define FLEET_ENROL_WHY_ONION_INVALID "join_onion_invalid"
#define FLEET_ENROL_WHY_RECEIPT_MALFORMED "receipt_malformed"
#define FLEET_ENROL_WHY_BOX_SIGNATURE "box_signature_invalid"
#define FLEET_ENROL_WHY_SIGNER_SIGNATURE "signing_key_signature_invalid"
#define FLEET_ENROL_WHY_ROSTER_UNREADABLE "roster_unreadable"
#define FLEET_ENROL_WHY_ROSTER_UNWRITABLE "roster_unwritable"
#define FLEET_ENROL_WHY_ROSTER_FULL "roster_full"
#define FLEET_ENROL_WHY_BRIDGE_UNWRITABLE "authorized_keys_unwritable"
#define FLEET_ENROL_WHY_ARGUMENTS "fleet_arguments_invalid"
#define FLEET_ENROL_WHY_ROSTER_LINE_UNSEALED "roster_line_not_operator_sealed"
#define FLEET_ENROL_WHY_OPERATOR_UNKNOWN "fleet_operator_unknown"
/* The operator-signed roster head (revocation), and the operator pin. */
#define FLEET_ENROL_WHY_HEAD_STALE "fleet_head_stale"
#define FLEET_ENROL_WHY_HEAD_CONFLICT "fleet_head_conflict"
#define FLEET_ENROL_WHY_HEAD_UNREADABLE "fleet_head_unreadable"
#define FLEET_ENROL_WHY_HEAD_INVALID "fleet_head_invalid"
#define FLEET_ENROL_WHY_HEAD_TOO_LARGE "fleet_head_too_large"
#define FLEET_ENROL_WHY_BOX_REVOKED "fleet_box_revoked"
#define FLEET_ENROL_WHY_ROOT_CHANGED "fleet_root_changed"
#define FLEET_ENROL_WHY_PIN_UNREADABLE "fleet_operator_pin_unreadable"
/* Another import holds the fleet state lock (or it cannot be taken): the
 * import is refused rather than racing the head or the pin. */
#define FLEET_ENROL_WHY_STATE_LOCK "fleet_state_locked"
/* The head sequence high-water mark is missing beside a head, or cannot be
 * read: owner repair, never read as zero. */
#define FLEET_ENROL_WHY_HEAD_HWM "fleet_head_hwm_unreadable"
/* A sequence record exists but the head it vouches for is missing, corrupt
 * or does not match: nobody is admitted. Re-importing the same head or a
 * higher one repairs it. */
#define FLEET_ENROL_WHY_HEAD_TORN "fleet_head_torn"
/* An import changed some state files and then failed: the pin or the
 * sequence record moved but the head did not. */
#define FLEET_ENROL_WHY_IMPORT_PARTIAL "fleet_import_partial"
/* A head would revoke a box whose roster row this operator does not hold,
 * so its signer key cannot be named: hold the row first. */
#define FLEET_ENROL_WHY_REVOKE_UNKNOWN "fleet_revoke_box_unknown"

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

/* The key a box will SIGN WITH once it runs a node: the DHT online key in
 * its datadir, which is what signs its board posts and its ledger rows.
 * It is NOT the box key above — that one lives under the state root and
 * identifies the machine to the roster. A box that has not started a node
 * yet has no signing key, and its receipt names none; see the receipt. */
struct fleet_signing_key {
    uint8_t pubkey[FLEET_ENROL_PUBKEY_BYTES];
    uint8_t seed[FLEET_ENROL_SEED_BYTES];
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
    /* The signing key above, or all zero when the box named none.
     * `signer_signature` is that key SIGNING this receipt up to and
     * including itself, so naming a key here proves possession of it
     * rather than merely asserting it. Receipts minted before this
     * field existed carry neither, and still parse. */
    uint8_t signer_pubkey[FLEET_ENROL_PUBKEY_BYTES];
    uint8_t signer_signature[FLEET_ENROL_SIG_BYTES];
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

/* The roster HEAD: one operator-sealed record naming the box public keys the
 * fleet has revoked, under a monotonic sequence number. Text form is
 * FLEET_HEAD_PREFIX then the same unpadded base64url body||signature a
 * machine row uses, sealed under its own domain so a row can never be
 * replayed as a head. The revoked set is canonical: strictly ascending, so
 * two heads with the same content are the same bytes and "equal sequence,
 * byte-identical" is a real test, not a guess. */
enum {
    FLEET_ENROL_HEAD_REVOKED_MAX = 256,
    /* version + operator key + seq + issued_at + count + keys + signature */
    FLEET_ENROL_HEAD_WIRE_MAX =
        1 + 32 + 8 + 8 + 2 + 256 * 32 + 64,
    FLEET_ENROL_HEAD_TEXT_MAX = (FLEET_ENROL_HEAD_WIRE_MAX * 4) / 3 + 24,
};
#define FLEET_HEAD_PREFIX "fleet-head1:"

struct fleet_head {
    uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES];
    uint64_t seq;           /* >= 1 */
    int64_t issued_at;
    uint32_t n_revoked;
    uint8_t revoked[FLEET_ENROL_HEAD_REVOKED_MAX][FLEET_ENROL_PUBKEY_BYTES];
    uint8_t signature[FLEET_ENROL_SIG_BYTES];
};

enum fleet_head_state {
    FLEET_HEAD_ABSENT = 0, /* no head file: nothing is revoked */
    FLEET_HEAD_OK,
    FLEET_HEAD_BAD,        /* a file exists and cannot be trusted: fail closed */
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

/* Read the node's own persistent onion hostname from
 * <datadir>/tor_data/onion_service/hostname (written by -onion-persist)
 * into `out`. True only when the file holds one valid locator; a missing,
 * unreadable, empty or invalid file leaves `out` empty and returns false,
 * which is the same column a box with no persistent onion records. */
bool fleet_enrol_onion_from_datadir(const char *datadir, char *out,
                                    size_t cap);

/* Mint a signed invite. `seed`/`pubkey` are this box's key. `text` receives
 * the unpadded base64url token. Refuses by name; writes nothing on refusal.
 *
 * The one-time nonce is drawn HERE, from the host CSPRNG, and overwrites
 * whatever `out` held: no caller supplies it, no caller can forget to, and
 * an uninitialised `struct fleet_invite` can never leak its stack bytes
 * into a signed token. A CSPRNG that refuses is
 * FLEET_ENROL_WHY_NONCE_UNAVAILABLE and mints nothing — an invite whose
 * nonce is predictable is an invite that admits one machine forever. */
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
 * refused by name when it is neither empty nor a v3 locator.
 *
 * `signer` is the key this box will SIGN board posts and ledger rows with
 * once it runs a node, or NULL when it has none yet. Naming it here is what
 * lets `fleet admit` grant a role to the key the enrolled box will actually
 * use, instead of only to the box key that identifies it. */
bool fleet_receipt_mint(const uint8_t *invite_wire, size_t invite_wire_len,
                        const char *onion,
                        const struct fleet_box_facts *facts,
                        const char *ssh_pubkey,
                        const uint8_t seed[FLEET_ENROL_SEED_BYTES],
                        const uint8_t pubkey[FLEET_ENROL_PUBKEY_BYTES],
                        const struct fleet_signing_key *signer,
                        char *text, size_t text_cap, const char **why);

/* Decode and VERIFY one receipt: the box signature over its own bytes AND
 * the operator signature on the invite it carries. Both must hold — and
 * when the receipt names a signing key, that key's own signature over the
 * receipt must hold as well, or the whole receipt is refused. */
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

/* Is this pasted line a roster head (as opposed to a machine row)? A prefix
 * test only; the seal is checked by fleet_head_parse. */
bool fleet_head_is_line(const char *line);

/* Seal a head under the operator key. `revoked` is `count` box keys of 32
 * bytes in any order; duplicates are collapsed and the set is sorted, so the
 * sealed head is canonical. `seq` is at least 1 and count at most
 * FLEET_ENROL_HEAD_REVOKED_MAX. Writes the text line. */
bool fleet_head_mint(uint64_t seq, int64_t issued_at, const uint8_t *revoked,
                     size_t count,
                     const uint8_t seed[FLEET_ENROL_SEED_BYTES],
                     const uint8_t pubkey[FLEET_ENROL_PUBKEY_BYTES],
                     char *text, size_t text_cap, const char **why);

/* Decode one head line and verify its seal under the operator key it
 * carries, and that the revoked set is canonical. It proves the head is
 * internally sealed, not that the operator is trusted: the caller compares
 * `out->operator_pubkey` with the key it trusts. */
bool fleet_head_parse(const char *text, struct fleet_head *out,
                      const char **why);

/* Is this box key revoked by the head? O(n_revoked). */
bool fleet_head_revokes(const struct fleet_head *head,
                        const uint8_t box_pubkey[FLEET_ENROL_PUBKEY_BYTES]);

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

/* Copy one roster line the manager sealed onto THIS box's roster — how a
 * box that is not the manager learns which other machines its fleet holds.
 * `operator_pubkey` is the key this box already trusts (the one `fleet
 * join` recorded, or its own on the manager); the line is appended only
 * after its operator seal verifies against exactly that key, so a line
 * sealed by any other key, or a sealed line with one byte changed, is
 * refused as FLEET_ENROL_WHY_ROSTER_LINE_UNSEALED and the roster is not
 * touched. The same box already on the roster is a no-op (`appended`
 * false); a different box under a name already taken is refused as
 * FLEET_ENROL_WHY_NAME_TAKEN. `out` receives the verified row. */
bool fleet_roster_import(const char *line,
                         const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                         struct fleet_machine *out, bool *appended,
                         const char **why);

/* fleet_roster_import with the operator pin made explicit. The pin
 * (`operator.pin`, the operator key this box first imported from) is
 * written on the first successful import; a later import under a different
 * operator key is refused as fleet_root_changed unless
 * `confirm_operator_change` is true, which re-pins. A machine row whose box
 * key the live head revokes is refused as fleet_box_revoked, and a head file
 * that cannot be trusted refuses every row as fleet_head_unreadable. */
bool fleet_roster_import_pinned(const char *line,
                                const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                                bool confirm_operator_change,
                                struct fleet_machine *out, bool *appended,
                                const char **why);

/* Roster-head storage. The current head lives beside the roster as
 * `roster.head`, replaced atomically (stage, flush, rename). A missing file
 * is FLEET_HEAD_ABSENT, nothing revoked. A file that exists and is empty,
 * unreadable, corrupt, or not sealed by `operator_pubkey` is FLEET_HEAD_BAD
 * with `why` naming it: callers fail closed on BAD, they never treat it as
 * empty. `out` is filled only for FLEET_HEAD_OK. */
enum fleet_head_state fleet_head_load(
    const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
    struct fleet_head *out, const char **why);

/* Import one head line sealed by `operator_pubkey`, the key this box trusts.
 * Refusals, by name: roster_line_not_operator_sealed (not a valid seal),
 * fleet_root_changed (sealed by a key this box does not trust, or the
 * operator pin differs and `confirm_operator_change` is false),
 * fleet_head_stale (lower sequence than the stored head),
 * fleet_head_conflict (same sequence, different bytes). The same sequence
 * and the same bytes succeeds with `replaced` false. A higher sequence
 * replaces the stored head. The operator pin is written on the first
 * success; `confirm_operator_change` re-pins. */
bool fleet_head_import(const char *line,
                       const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                       bool confirm_operator_change, struct fleet_head *out,
                       bool *replaced, const char **why);

#ifdef ZCL_TESTING
/* Test seams: how long a state-lock wait lasts, a call made inside the
 * head import after the sequence check and before anything is written, and
 * a simulated crash between the sequence record and the head. */
extern int fleet_enrol_test_lock_wait_ms;
extern void (*fleet_enrol_test_after_check)(void);
extern bool fleet_enrol_test_crash_before_head;
extern bool fleet_enrol_test_fail_pin_write;
extern bool fleet_enrol_test_fail_floor;
extern bool fleet_enrol_test_fail_dir_flush;
#endif

/* Visit every line of this box's own machine roster file, verbatim and in
 * file order, without parsing it: the lines the manager publishes onto the
 * board as roster rows. A line longer than one machine line can be is
 * skipped. Returns false only when the roster cannot be read at all. */
bool fleet_roster_each_line(void (*visit)(const char *line, void *user),
                            void *user, const char **why);

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

/* Every signer key the operator's own roster rows bind to `box_pubkey` (at
 * most `cap`; more refuses as fleet_head_too_large): `found` is false when no
 * row for the box is held. A head that revokes a box must also revoke each of
 * its signers, because the relay gate sees only the signer. */
bool fleet_roster_signers_of_box(
    const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
    const uint8_t box_pubkey[FLEET_ENROL_PUBKEY_BYTES],
    uint8_t (*signers)[FLEET_ENROL_PUBKEY_BYTES], size_t cap, size_t *count,
    bool *found, const char **why);

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
 * second grant. Refuses when HOME is unset or the file cannot be written.
 * An embedded NUL in the measured file refuses before searching or appending,
 * leaving the file bytes unchanged and `added` false. */
bool fleet_bridge_authorize(const char *line, const char *name, bool *added,
                            const char **why);

/* ── the fleet root as a ZID anchor (tools/dev/fleet_enrol_anchor.c) ─────── */

/* ZRC 0012 step 1. The fleet operator key is a 32-byte Ed25519 key, the same
 * shape as a ZID master key, so "fleet root = ZID anchor" needs NO second key
 * format and changes NO signed byte: the operator anchors the very pubkey
 * `fleet invite` prints with `core identity anchor`, and a node answers "is
 * the key that sealed this roster line an active anchor?" from its own
 * zid_identities projection. "Sealed by the operator" and "the operator is
 * anchored" stay two separate facts. The projection lookup lives in the
 * adapter (tools/command/native_fleet_enrol_command.c); everything here is
 * pure, so a later roster gate can call the same verdicts. */
enum fleet_anchor_state {
    FLEET_ANCHOR_UNCHECKED = 0, /* no datadir / no node.db: nobody looked */
    FLEET_ANCHOR_UNREADABLE,    /* node.db exists and could not be read */
    FLEET_ANCHOR_NOT_ANCHORED,  /* looked: no row for this key */
    FLEET_ANCHOR_ACTIVE,
    FLEET_ANCHOR_ROTATED,       /* superseded; `successor` is set */
    FLEET_ANCHOR_REVOKED,
};

struct fleet_anchor_fact {
    enum fleet_anchor_state state;
    int32_t anchor_height;
    bool has_successor;
    uint8_t successor[FLEET_ENROL_PUBKEY_BYTES];
};

/* Typed refusals for a fleet root that must be anchored. */
#define FLEET_ENROL_WHY_ROOT_NOT_ANCHORED "fleet_root_not_anchored"
#define FLEET_ENROL_WHY_ROOT_ROTATED "fleet_root_rotated"
#define FLEET_ENROL_WHY_ROOT_REVOKED "fleet_root_revoked"
#define FLEET_ENROL_WHY_ROOT_UNVERIFIABLE "fleet_root_anchor_unverifiable"
/* The ZRC 0012 condition name for a roster row whose seal does not verify
 * under the fleet root. Used as a refusal token here; it raises no standing
 * blocker, because the ZRC says it self-clears per row. */
#define FLEET_ENROL_WHY_ROSTER_SIGNATURE "fleetboard.roster_signature_invalid"

const char *fleet_anchor_state_name(enum fleet_anchor_state state);

/* The fail-closed verdict. NULL when the root is acceptable; otherwise the
 * typed token. With `require` false it always returns NULL: an enrolment
 * made before the root was anchored still reads, and its state is REPORTED
 * (fleet_anchor_state_name), not rejected. With `require` true only ACTIVE
 * passes; UNCHECKED and UNREADABLE fail closed as "unverifiable". */
const char *fleet_root_anchor_refusal(const struct fleet_anchor_fact *anchor,
                                      bool require);

/* One roster line against one root: the seal first (a line the root did not
 * seal is `fleetboard.roster_signature_invalid`, whatever the chain says),
 * then the anchor verdict. `out` is filled on a verified seal even when the
 * anchor verdict refuses, so a caller can name the machine it refused. */
bool fleet_root_line_verify(const char *line,
                            const uint8_t root[FLEET_ENROL_PUBKEY_BYTES],
                            const struct fleet_anchor_fact *anchor,
                            bool require, struct fleet_machine *out,
                            const char **why);

/* ── the roster gate provider (tools/dev/fleet_roster_gate.c) ─────────────── */

/* ZRC 0012 step 2. The fleet board lives under engine/, which may not
 * include this header, so it asks util/fleet_roster_check.h; this fills that
 * seam in with the operator root this box trusts, `fleet_root_line_verify`
 * and this box's roster file. Called once from engine/entry/main.c. */
struct zcl_fleet_roster_provider;
const struct zcl_fleet_roster_provider *zcl_fleet_roster_gate_provider(void);
void zcl_fleet_roster_gate_start(void);

#endif /* ZCL_TOOLS_DEV_FLEET_ENROL_H */
