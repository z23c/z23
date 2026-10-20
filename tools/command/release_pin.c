/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: owner-key pin set, shared release gate and .zid file reader.
 *          See release_pin.h.
 */

#include "command/release_pin.h"

#include "command/native_command.h"
#include "command/native_slot_common.h"

#include "base/hex.h"
#include "crypto/sha256.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "zid/zid.h"

#include <stdio.h>
#include <string.h>

void release_pin_fingerprint(const uint8_t pubkey[32],
                             char out[RELEASE_PIN_FINGERPRINT_HEX + 1])
{
    struct sha256_ctx ctx;
    unsigned char digest[SHA256_OUTPUT_SIZE];
    sha256_init(&ctx);
    sha256_write(&ctx, pubkey, 32);
    sha256_finalize(&ctx, digest);
    zcl_hex_encode(digest, RELEASE_PIN_FINGERPRINT_HEX / 2u, out);
}

bool release_pin_contains(const struct release_pin_set *set,
                          const uint8_t pubkey[32])
{
    for (size_t i = 0; set && i < set->count; i++)
        if (memcmp(set->keys[i], pubkey, 32) == 0)
            return true;
    for (size_t i = 0; set && i < set->pair_count; i++)
        if (memcmp(set->pairs[i].ed, pubkey, 32) == 0)
            return true;
    return false;
}

static bool rp_has_key(const struct release_pin_set *set,
                       const uint8_t pubkey[32])
{
    for (size_t i = 0; i < set->count; i++)
        if (memcmp(set->keys[i], pubkey, 32) == 0)
            return true;
    return false;
}

static bool rp_full(const struct release_pin_set *set,
                    struct zcl_command_reply *reply, const char *command)
{
    if (set->count + set->pair_count < RELEASE_PIN_MAX)
        return false;
    zcl_native_refuse(reply, "TOO_MANY_PINS", "normalize",
            "the pin set holds at most 256 distinct owner pins", command);
    return true;
}

static bool rp_add(struct release_pin_set *set, const char *hex,
                   struct zcl_command_reply *reply, const char *command)
{
    uint8_t key[32];
    if (!zcl_hex_decode(hex, key, sizeof(key))) {
        zcl_native_refuse(reply, "BAD_PIN", "normalize",
                "a pin is an owner's Ed25519 public key: exactly 64 hex "
                "characters, or `zrs1 <ed25519 hex> 0 <slh-dsa pk hex>`",
                command);
        return false;
    }
    if (rp_has_key(set, key))
        return true;
    if (rp_full(set, reply, command))
        return false;
    memcpy(set->keys[set->count++], key, sizeof(key));
    return true;
}

/* Parse `zrs1 <ed25519_hex64> <param> <slhdsa_pk_hex64>` (already trimmed).
 * True and *pair filled on a well-formed line; the only accepted param is
 * the SLH-DSA-SHAKE-128s id 0, whose public key is 32 bytes. */
static bool rp_parse_pair(const char *text, struct release_pin_pair *pair)
{
    char buf[256];
    char *tok[5];
    size_t n = 0;
    if (strlen(text) >= sizeof(buf))
        return false;
    memcpy(buf, text, strlen(text) + 1);
    for (char *p = strtok(buf, " \t"); p && n < 5; p = strtok(NULL, " \t"))
        tok[n++] = p;
    if (n != 4 || strcmp(tok[0], RELEASE_PIN_PAIR_TAG) != 0 ||
        strcmp(tok[2], "0") != 0)
        return false;
    return strlen(tok[1]) == 64 && strlen(tok[3]) == ZRS1_PQ_PK_SIZE * 2u &&
           zcl_hex_decode(tok[1], pair->ed, sizeof(pair->ed)) &&
           zcl_hex_decode(tok[3], pair->pq, sizeof(pair->pq));
}

static bool rp_add_pair(struct release_pin_set *set, const char *text,
                        struct zcl_command_reply *reply, const char *command)
{
    struct release_pin_pair pair;
    if (!rp_parse_pair(text, &pair)) {
        zcl_native_refuse(reply, "BAD_PIN", "normalize",
                "a pair pin is `zrs1 <64-hex Ed25519 key> 0 <64-hex "
                "SLH-DSA-SHAKE-128s public key>`", command);
        return false;
    }
    for (size_t i = 0; i < set->pair_count; i++)
        if (memcmp(&set->pairs[i], &pair, sizeof(pair)) == 0)
            return true;
    if (rp_full(set, reply, command))
        return false;
    set->pairs[set->pair_count++] = pair;
    return true;
}

static bool rp_is_pair_text(const char *s)
{
    size_t n = strlen(RELEASE_PIN_PAIR_TAG);
    return strncmp(s, RELEASE_PIN_PAIR_TAG, n) == 0 &&
           (s[n] == ' ' || s[n] == '\t' || s[n] == '\0');
}

/* Trim ASCII whitespace from both ends of a line in place. */
static char *rp_trim(char *s)
{
    while (*s == ' ' || *s == '\t' || *s == '\r')
        s++;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' ||
                     s[n - 1] == '\r' || s[n - 1] == '\n'))
        s[--n] = '\0';
    return s;
}

/* `threshold K`: K is plain decimal digits. Returns the typed refusal code
 * through `reply`; false when the line is refused. */
static bool rp_threshold_line(struct release_pin_set *set, const char *rest,
                              size_t lineno, struct zcl_command_reply *reply,
                              const char *path)
{
    char where[64];
    snprintf(where, sizeof(where), "line %zu", lineno);
    while (*rest == ' ' || *rest == '\t')
        rest++;
    size_t n = strlen(rest), k = 0;
    bool digits = n > 0 && n <= 4;
    for (size_t i = 0; digits && i < n; i++) {
        digits = rest[i] >= '0' && rest[i] <= '9';
        k = k * 10u + (size_t)(rest[i] - '0');
    }
    if (!digits || set->threshold_seen) {
        zcl_native_refuse(reply, "PIN_FILE_INVALID", "normalize",
                "a pin file holds at most one `threshold <K>` line, K "
                "written as decimal digits", where);
        return false;
    }
    set->threshold_seen = true;
    if (k < 1) {
        zcl_native_refuse(reply, "THRESHOLD_BELOW_ONE", "normalize",
                "a release threshold must be at least 1; remove the "
                "`threshold` line to keep single-signer behaviour", path);
        return false;
    }
    set->threshold = k;
    set->require_pq = true; /* a threshold counts hybrid pairs only */
    return true;
}

static bool rp_is_directive(const char *key, const char *word)
{
    size_t n = strlen(word);
    return strncmp(key, word, n) == 0 &&
           (key[n] == '\0' || key[n] == ' ' || key[n] == '\t');
}

static bool rp_pin_line(struct release_pin_set *set, char *line, size_t lineno,
                        struct zcl_command_reply *reply, const char *path)
{
    char *key = rp_trim(line);
    if (key[0] == '\0' || key[0] == '#')
        return true;
    if (strcmp(key, RELEASE_PIN_REQUIRE_PQ_LINE) == 0) {
        set->require_pq = true;
        return true;
    }
    if (rp_is_directive(key, RELEASE_PIN_THRESHOLD_LINE))
        return rp_threshold_line(set, key + strlen(RELEASE_PIN_THRESHOLD_LINE),
                                 lineno, reply, path);
    char where[64];
    snprintf(where, sizeof(where), "line %zu", lineno);
    if (rp_is_pair_text(key)) {
        struct release_pin_pair pair;
        if (!rp_parse_pair(key, &pair)) {
            zcl_native_refuse(reply, "PIN_FILE_INVALID", "normalize",
                    "a pair line must be `zrs1 <64-hex Ed25519 key> 0 "
                    "<64-hex SLH-DSA-SHAKE-128s public key>`", where);
            return false;
        }
        return rp_add_pair(set, key, reply, path);
    }
    uint8_t probe[32];
    if (!zcl_hex_decode(key, probe, sizeof(probe))) {
        zcl_native_refuse(reply, "PIN_FILE_INVALID", "normalize",
                "every non-comment line of a pin file must be one 64-hex "
                "owner public key, a `zrs1` pair line, or `require-pq`",
                where);
        return false;
    }
    return rp_add(set, key, reply, path);
}

static bool rp_load_file(struct release_pin_set *set, const char *path,
                         struct zcl_command_reply *reply)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        zcl_native_refuse(reply, "PIN_FILE_UNREADABLE", "normalize",
                "cannot open the owner-pins file; it must be a local file "
                "listing one 64-hex owner public key per line", path);
        return false;
    }
    char line[256];
    size_t lineno = 0, total = 0, before = set->count + set->pair_count;
    bool ok = true;
    while (ok && fgets(line, sizeof(line), fp)) {
        total += strlen(line);
        lineno++;
        if (total > RELEASE_PIN_FILE_MAX_BYTES ||
            (!strchr(line, '\n') && !feof(fp))) {
            zcl_native_refuse(reply, "PIN_FILE_INVALID", "normalize",
                    "pin file lines must be short and the file at most "
                    "64 KiB", path);
            ok = false;
            break;
        }
        ok = rp_pin_line(set, line, lineno, reply, path);
    }
    fclose(fp);
    if (ok && set->count + set->pair_count == before) {
        zcl_native_refuse(reply, "PIN_FILE_EMPTY", "normalize",
                "the owner-pins file lists no keys, so nothing could ever "
                "be trusted from it; add the owner's 64-hex public key",
                path);
        ok = false;
    }
    return ok;
}

static bool rp_flag(const struct json_value *in, const char *key)
{
    const struct json_value *v = json_get(in, key);
    if (!v)
        return false;
    if (v->type == JSON_BOOL)
        return json_get_bool(v);
    if (v->type == JSON_INT)
        return json_get_int(v) != 0;
    const char *s = v->type == JSON_STR ? json_get_str(v) : NULL;
    return s && (strcmp(s, "true") == 0 || strcmp(s, "1") == 0);
}

bool release_pin_collect(const struct json_value *in,
                         struct release_pin_set *set,
                         struct zcl_command_reply *reply, const char *command)
{
    memset(set, 0, sizeof(*set));
    const struct json_value *pin = json_get(in, "pin");
    const struct json_value *file = json_get(in, "pin_file");
    const char *pin_s = pin ? json_get_str(pin) : NULL;
    const char *file_s = file ? json_get_str(file) : NULL;
    if ((pin && !pin_s) || (file && !file_s)) {
        zcl_native_refuse(reply, "BAD_PIN", "normalize",
                "pin and pin_file must be strings", command);
        return false;
    }
    set->require_pq = rp_flag(in, "require_pq");
    if (pin_s) {
        set->given = true;
        if (!(rp_is_pair_text(pin_s) ? rp_add_pair(set, pin_s, reply, command)
                                     : rp_add(set, pin_s, reply, command)))
            return false;
    }
    if (file_s) {
        set->given = true;
        if (!rp_load_file(set, file_s, reply))
            return false;
    }
    if (set->threshold > set->pair_count) {
        zcl_native_refuse(reply, "THRESHOLD_EXCEEDS_PINS", "normalize",
                "the pin file asks for more distinct signers than it pins "
                "hybrid pairs (`zrs1` lines; a pair pinned twice counts "
                "once)", command);
        return false;
    }
    return true;
}

/* A signer refusal: `code` names which pin rule failed. */
static bool rp_refuse_signer(struct zcl_command_reply *reply,
                             const char *code, const char *tail,
                             const uint8_t signer[32])
{
    char fp[RELEASE_PIN_FINGERPRINT_HEX + 1], hex[65], msg[400];
    release_pin_fingerprint(signer, fp);
    zcl_hex_encode(signer, 32, hex);
    snprintf(msg, sizeof(msg), "this release is signed by owner key %s%s", fp,
             tail);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, "execute", false,
                           false, msg, hex);
    return false;
}

static bool rp_unpinned(struct zcl_command_reply *reply,
                        const uint8_t signer[32])
{
    return rp_refuse_signer(
        reply, "RELEASE_UNPINNED",
        ", which is not in your pins; if you have confirmed that key out of "
        "band, add its 64-hex public key to your owner-pins file and retry",
        signer);
}

static bool rp_root_check(const struct json_value *in,
                          const uint8_t manifest_root[32],
                          struct zcl_command_reply *reply, const char *command)
{
    const struct json_value *v = json_get(in, "package_root");
    if (!v)
        return true;
    const char *hex = json_get_str(v);
    uint8_t want[32];
    char err[128];
    if (!zcl_native_require_hex64("package_root", hex, want, err,
                                  sizeof(err))) {
        zcl_native_refuse(reply, "BAD_ROOT", "normalize", err, command);
        return false;
    }
    if (memcmp(want, manifest_root, 32) == 0)
        return true;
    char got[65];
    zcl_hex_encode(manifest_root, 32, got);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, "RELEASE_ROOT_MISMATCH",
                           "execute", false, false,
                           "the package root you expect is not the root this "
                           "signed release commits to; these are not the "
                           "bytes the owner released",
                           got);
    return false;
}

static bool rp_need_pin(const struct release_pin_set *set, bool require_pin,
                        struct zcl_command_reply *reply, const char *command)
{
    if (!require_pin || set->given)
        return true;
    zcl_native_refuse(reply, "PIN_REQUIRED", "normalize",
            "installing needs an owner pin: pass pin=<64-hex owner "
            "public key> or pin_file=<local owner-pins file>; there is "
            "no unpinned install", command);
    return false;
}

bool release_pin_gate(const struct json_value *in, bool require_pin,
                      const uint8_t signer[32], const uint8_t manifest_root[32],
                      struct zcl_command_reply *reply, const char *command)
{
    struct release_pin_set set;
    if (!release_pin_collect(in, &set, reply, command))
        return false;
    if (!rp_need_pin(&set, require_pin, reply, command))
        return false;
    if (set.given && !release_pin_contains(&set, signer))
        return rp_unpinned(reply, signer);
    if (set.require_pq)
        return rp_refuse_signer(
            reply, "RELEASE_PQ_REQUIRED",
            " with a v1 (Ed25519-only) doc, but your pins require a "
            "post-quantum hybrid (v2) release; ask the owner for a ZRS1 "
            "v2 doc",
            signer);
    return rp_root_check(in, manifest_root, reply, command);
}

/* The pair pin that governs a v2 doc: the one matching both its master key
 * and container key, else the first for its master key (the verifier then
 * reports PQ_KEY_MISMATCH). NULL when no pair names this master key. */
static const struct release_pin_pair *
rp_pair_for(const struct release_pin_set *set, const struct zid_doc_v2 *v2)
{
    const struct release_pin_pair *found = NULL;
    for (size_t i = 0; i < set->pair_count; i++) {
        const struct release_pin_pair *p = &set->pairs[i];
        if (memcmp(p->ed, v2->master_pubkey, 32) != 0)
            continue;
        if (memcmp(p->pq, v2->pq_pk, ZRS1_PQ_PK_SIZE) == 0)
            return p;
        if (!found)
            found = p;
    }
    return found;
}

/* Verify one v2 doc against its governing pair pin (NULL: authenticate the
 * pair the doc names, unpinned). Fills `rel` and sets d->pq_verified. */
static bool rp_verify_v2(struct release_pin_doc *d,
                         const struct release_pin_pair *pair,
                         uint64_t now_unix, struct zid_release *rel,
                         struct zcl_command_reply *reply, const char *command)
{
    enum zid_hybrid_status st = zid_hybrid_release_verify(
        &d->v2, pair ? pair->pq : NULL, rel, now_unix);
    if (st != ZID_HYBRID_OK) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED,
                               zid_hybrid_status_code(st), "execute", false,
                               false,
                               "the v2 hybrid release doc did not verify "
                               "against your pinned pair; both the Ed25519 "
                               "and the SLH-DSA signature must hold",
                               command);
        return false;
    }
    d->pq_verified = true;
    return true;
}

bool release_pin_doc_gate(const struct json_value *in, bool require_pin,
                          struct release_pin_doc *d, uint64_t now_unix,
                          struct zid_release *rel,
                          struct zcl_command_reply *reply, const char *command)
{
    d->pq_verified = false;
    if (d->version != ZID_DOC_VERSION_V2)
        return release_pin_gate(in, require_pin, d->doc.master_pubkey,
                                rel->manifest_root, reply, command);
    struct release_pin_set set;
    if (!release_pin_collect(in, &set, reply, command) ||
        !rp_need_pin(&set, require_pin, reply, command))
        return false;
    const struct release_pin_pair *pair = rp_pair_for(&set, &d->v2);
    if (set.given && !pair) {
        if (!release_pin_contains(&set, d->v2.master_pubkey))
            return rp_unpinned(reply, d->v2.master_pubkey);
        return rp_refuse_signer(
            reply, "RELEASE_PQ_UNPINNED",
            ", pinned only as an Ed25519 key; a v2 hybrid release needs a "
            "pair pin (`zrs1 <ed25519 hex> 0 <slh-dsa pk hex>`) so the "
            "post-quantum half is held to a key you chose",
            d->v2.master_pubkey);
    }
    if (!rp_verify_v2(d, pair, now_unix, rel, reply, command))
        return false;
    return rp_root_check(in, rel->manifest_root, reply, command);
}

/* Read at most max_chars of a file into hex, trailing whitespace trimmed.
 * Returns the length, or 0 when unreadable, empty or oversize. */
static size_t rp_slurp(const char *path, size_t max_chars, char *hex)
{
    FILE *fp = path ? fopen(path, "rb") : NULL;
    if (!fp)
        return 0;
    size_t n = fread(hex, 1, max_chars, fp);
    bool oversize = !feof(fp);
    fclose(fp);
    while (n > 0 && (hex[n - 1] == '\n' || hex[n - 1] == '\r' ||
                     hex[n - 1] == ' '))
        n--;
    hex[n] = '\0';
    return oversize ? 0 : n;
}

/* Read the hex text of a saved doc into wire; false with *code set. */
static bool rp_read_wire(const char *path, size_t max_chars, uint8_t *wire,
                         size_t wire_cap, size_t *wire_len,
                         const char **code)
{
    char hex[ZID_DOC_V2_MAX * 2 + 2];
    size_t n = rp_slurp(path, max_chars, hex);
    *code = "DOC_UNREADABLE";
    if (n == 0)
        return false;
    *code = "BAD_DOC_HEX";
    if ((n & 1u) || n / 2u > wire_cap || !zcl_hex_decode(hex, wire, n / 2u))
        return false;
    *wire_len = n / 2u;
    return true;
}

bool release_pin_read_doc(const char *path, struct zid_doc *doc,
                          const char **code)
{
    uint8_t wire[ZID_DOC_V2_MAX];
    size_t wire_len = 0;
    if (!rp_read_wire(path, ZID_DOC_MAX * 2u + 1u, wire, sizeof(wire),
                      &wire_len, code))
        return false;
    *code = "DOC_DECODE_FAILED";
    return wire_len <= ZID_DOC_MAX && zid_doc_decode(doc, wire, wire_len);
}

bool release_pin_read_any(const char *path, struct release_pin_doc *d,
                          const char **code)
{
    uint8_t wire[ZID_DOC_V2_MAX];
    size_t wire_len = 0;
    memset(d, 0, sizeof(*d));
    if (!rp_read_wire(path, ZID_DOC_V2_MAX * 2u + 1u, wire, sizeof(wire),
                      &wire_len, code))
        return false;
    if (wire[0] != ZID_DOC_VERSION_V2) {
        d->version = ZID_DOC_VERSION;
        *code = "DOC_DECODE_FAILED";
        return wire_len <= ZID_DOC_MAX &&
               zid_doc_decode(&d->doc, wire, wire_len);
    }
    d->version = ZID_DOC_VERSION_V2;
    enum zid_hybrid_status st = zid_hybrid_decode(&d->v2, wire, wire_len);
    *code = zid_hybrid_status_code(st);
    if (st != ZID_HYBRID_OK)
        return false;
    memcpy(d->doc.master_pubkey, d->v2.master_pubkey, 32);
    d->doc.seq = d->v2.seq;
    d->doc.expiry = d->v2.expiry;
    d->doc.body_len = d->v2.body_len;
    memcpy(d->doc.body, d->v2.body, d->v2.body_len);
    return true;
}

/* ── k-of-n owner gate ─────────────────────────────────────────────── */

bool release_pin_threshold_active(const struct json_value *in)
{
    const struct json_value *cs = json_get(in, "cosigs");
    const char *cos = cs ? json_get_str(cs) : NULL;
    if (cos && cos[0])
        return true;
    struct zcl_command_reply scratch;
    struct release_pin_set set;
    zcl_command_reply_init(&scratch, "zcl.release_pin.probe.v1");
    bool ok = release_pin_collect(in, &set, &scratch, "release_pin");
    zcl_command_reply_free(&scratch);
    return ok && set.threshold > 0;
}

static bool rp_same_release(const struct zid_release *a,
                            const struct zid_release *b)
{
    return strcmp(a->name, b->name) == 0 &&
           strcmp(a->version, b->version) == 0 &&
           memcmp(a->manifest_root, b->manifest_root, 32) == 0;
}

/* Running state of one threshold check. Docs are read one at a time and only
 * their signer identity is kept, so the set needs no heap. */
struct rp_tally {
    const struct release_pin_set *set;
    uint64_t now_unix;
    struct zcl_command_reply *reply;
    const char *command;
    uint8_t seen_ed[RELEASE_PIN_MAX_DOCS][32];
    uint8_t seen_pq[RELEASE_PIN_MAX_DOCS][ZRS1_PQ_PK_SIZE];
    size_t seen;
    size_t matched;
    struct zid_release first; /* the release every counted doc agrees on */
};

/* One doc into the tally. A v1 doc, a second doc by one signer (the same
 * pair, or a shared Ed25519 or SLH-DSA key) and a pinned doc that does not
 * verify each refuse the whole set; a doc by an unpinned pair counts zero;
 * verified docs must all agree on name, version and root. */
static bool rp_tally_doc(struct rp_tally *t, struct release_pin_doc *d)
{
    struct zid_release r;
    if (d->version != ZID_DOC_VERSION_V2)
        return rp_refuse_signer(
            t->reply, "RELEASE_PQ_REQUIRED",
            " with a v1 (Ed25519-only) doc, but a threshold counts "
            "post-quantum hybrid (v2) pairs only", d->doc.master_pubkey);
    for (size_t i = 0; i < t->seen; i++)
        if (memcmp(t->seen_ed[i], d->v2.master_pubkey, 32) == 0 ||
            memcmp(t->seen_pq[i], d->v2.pq_pk, ZRS1_PQ_PK_SIZE) == 0)
            return rp_refuse_signer(
                t->reply, "THRESHOLD_DUPLICATE_SIGNER",
                " on more than one doc of this set; one signer counts "
                "once, so a threshold needs docs from different pairs",
                d->v2.master_pubkey);
    memcpy(t->seen_ed[t->seen], d->v2.master_pubkey, 32);
    memcpy(t->seen_pq[t->seen], d->v2.pq_pk, ZRS1_PQ_PK_SIZE);
    t->seen++;
    const struct release_pin_pair *pair = rp_pair_for(t->set, &d->v2);
    if (!pair)
        return true;
    memset(&r, 0, sizeof(r));
    if (!rp_verify_v2(d, pair, t->now_unix, &r, t->reply, t->command))
        return false;
    if (t->matched == 0)
        t->first = r;
    else if (!rp_same_release(&t->first, &r)) {
        zcl_native_refuse(t->reply, "THRESHOLD_DISAGREE", "execute",
                "the signers did not sign the same release: name, "
                "version and package root must be identical in every "
                "doc", t->command);
        return false;
    }
    t->matched++;
    return true;
}

/* Read each comma-separated saved .zid path of `cos` through the same reader
 * as the primary doc and tally it. */
static bool rp_tally_cosigs(struct rp_tally *t, const char *cos)
{
    struct release_pin_doc cur;
    while (cos && cos[0]) {
        const char *comma = strchr(cos, ',');
        size_t len = comma ? (size_t)(comma - cos) : strlen(cos);
        char path[1024];
        const char *code = NULL;
        if (len == 0 || len >= sizeof(path)) {
            zcl_native_refuse(t->reply, "BAD_COSIGS", "normalize",
                    "cosigs is a comma-separated list of saved .zid file "
                    "paths, none empty", t->command);
            return false;
        }
        if (t->seen >= RELEASE_PIN_MAX_DOCS) {
            zcl_native_refuse(t->reply, "TOO_MANY_DOCS", "normalize",
                    "a threshold set holds at most 8 docs", t->command);
            return false;
        }
        memcpy(path, cos, len);
        path[len] = '\0';
        if (!release_pin_read_any(path, &cur, &code)) {
            zcl_native_refuse(t->reply, code, "normalize",
                    "a cosigner release doc could not be read as a saved "
                    ".zid (hex text)", path);
            return false;
        }
        if (!rp_tally_doc(t, &cur))
            return false;
        cos = comma ? comma + 1 : cos + len;
    }
    return true;
}

/* Refusals that need no doc: no pin, cosigners without a threshold, and
 * one doc when K >= 2. */
static bool rp_threshold_preflight(const struct release_pin_set *set,
                                   const char *cos, bool require_pin,
                                   struct zcl_command_reply *reply,
                                   const char *command)
{
    if (!rp_need_pin(set, require_pin, reply, command))
        return false;
    if (set->threshold == 0) {
        zcl_native_refuse(reply, "THRESHOLD_MISSING", "normalize",
                "cosigner docs were given but the pin file has no "
                "`threshold <K>` line; extra docs are never ignored",
                command);
        return false;
    }
    if ((!cos || !cos[0]) && set->threshold >= 2) {
        zcl_native_refuse(reply, "THRESHOLD_SINGLE_DOC", "execute",
                "your pins require K distinct signers but only one doc "
                "was given; pass the other signers' docs in cosigs",
                command);
        return false;
    }
    return true;
}

/* Tally the primary and cosigner docs and compare with K. */
static bool rp_threshold_run(const struct json_value *in,
                             const struct release_pin_set *set,
                             const char *cos, struct release_pin_doc *d,
                             uint64_t now_unix, struct zid_release *rel,
                             struct release_pin_threshold *out,
                             struct zcl_command_reply *reply,
                             const char *command)
{
    struct rp_tally t = { .set = set, .now_unix = now_unix, .reply = reply,
                          .command = command };
    d->pq_verified = false;
    if (!rp_tally_doc(&t, d) || !rp_tally_cosigs(&t, cos))
        return false;
    if (t.matched < set->threshold) {
        zcl_native_refuse(reply, "THRESHOLD_NOT_MET", "execute",
                "fewer distinct pinned pairs signed this release than your "
                "pins require", command);
        return false;
    }
    *rel = t.first;
    if (out) {
        out->threshold = set->threshold;
        out->matched = t.matched;
    }
    return rp_root_check(in, rel->manifest_root, reply, command);
}

bool release_pin_multi_gate(const struct json_value *in, bool require_pin,
                            struct release_pin_doc *d, uint64_t now_unix,
                            struct zid_release *rel,
                            struct release_pin_threshold *out,
                            struct zcl_command_reply *reply,
                            const char *command)
{
    if (out)
        memset(out, 0, sizeof(*out));
    const struct json_value *cs = json_get(in, "cosigs");
    const char *cos = cs ? json_get_str(cs) : NULL;
    if (cs && !cos) {
        zcl_native_refuse(reply, "BAD_COSIGS", "normalize",
                "cosigs must be a string", command);
        return false;
    }
    struct release_pin_set set;
    if (!release_pin_collect(in, &set, reply, command))
        return false;
    if (set.threshold == 0 && !(cos && cos[0]))
        return release_pin_doc_gate(in, require_pin, d, now_unix, rel, reply,
                                    command);
    if (!rp_threshold_preflight(&set, cos, require_pin, reply, command))
        return false;
    return rp_threshold_run(in, &set, cos, d, now_unix, rel, out, reply,
                            command);
}
