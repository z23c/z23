/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The tamper-evident audit log: one signed, hash-chained receipt per action the
 * confined agent took through the broker.
 *
 * WHY A CHAIN AND A SIGNATURE, not just a log file: a plain log is evidence
 * only against an adversary who does not have the file. The broker's own
 * directory is writable by the operator, so the useful property is not secrecy
 * but DETECTABILITY — after the fact, anyone with the public key can prove
 * whether the log they are holding is the log the broker wrote. Each receipt's
 * id commits to the previous receipt's id, so deleting or reordering a row
 * breaks a link; each id is Ed25519-signed, so editing a field inside a row
 * either changes the recomputed id (chain break) or leaves the signature over
 * a different id (signature failure). agent_audit_verify_dir() reports which.
 *
 * The signing key is generated on first open and the SECRET half never leaves
 * this process's memory. The confined child has no Landlock grant on the
 * broker's directory, so it cannot read even the public half, let alone forge.
 */

#include "session/agent_broker.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "platform/clock.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"
#include "platform/rng.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define AUDIT_TAG "agent.audit"
#define AUDIT_FILE_MAX (64u << 20)

static bool audit_read_stable(const char *path, size_t cap, char **out,
                              size_t *out_size)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    *out = NULL;
    *out_size = 0;
    if (!platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_snapshot(&file, &before) ||
        before.size > cap || before.size > SIZE_MAX - 1) {
        platform_positioned_file_close(&file);
        return false;
    }
    char *data = zcl_malloc((size_t)before.size + 1, "agent_audit_read");
    if (!data) {
        platform_positioned_file_close(&file);
        return false;
    }
    size_t done = 0;
    while (done < before.size) {
        int64_t got = platform_positioned_file_read(
            &file, data + done, (size_t)before.size - done, done);
        if (got <= 0) break;
        done += (size_t)got;
    }
    bool stable = done == before.size &&
        platform_positioned_file_snapshot(&file, &after) &&
        before.size == after.size && before.volume == after.volume &&
        before.file_low == after.file_low && before.file_high == after.file_high &&
        before.modified_seconds == after.modified_seconds &&
        before.modified_nanoseconds == after.modified_nanoseconds &&
        before.changed_seconds == after.changed_seconds &&
        before.changed_nanoseconds == after.changed_nanoseconds;
    platform_positioned_file_close(&file);
    if (!stable) { free(data); return false; }
    data[done] = '\0';
    *out = data;
    *out_size = done;
    return true;
}

/* One receipt line stays well under this; the reader rejects anything longer
 * rather than splitting a row it cannot parse. */
#define AUDIT_LINE_MAX 2048

/* ── the canonical receipt preimage ─────────────────────────────────────── */

/* Everything a verifier must be unable to change without detection goes in
 * here, length-prefixed where variable so no two field sets can collide. */
static void receipt_digest(const struct agent_receipt *r, uint8_t out[32])
{
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    const bool v3 = r->receipt_version >= 3;
    sha3_256_write(&c, (const unsigned char *)(v3
                       ? "zcl.agent_receipt.v3" : "zcl.agent_receipt.v2"),
                   20);
    sha3_256_write(&c, r->prev, 32);

    uint8_t n[7][8];
    uint64_t vals[7] = {
        r->seq, (uint64_t)r->unix_ms, (uint64_t)r->verb,
        (uint64_t)r->request_id, (uint64_t)(uint32_t)r->status,
        r->value_zats,
        ((uint64_t)(uint32_t)r->peer.pid << 32) | (uint32_t)r->peer.uid,
    };
    for (size_t i = 0; i < 7; i++)
        zcl_write_u64_le(n[i], vals[i]);
    sha3_256_write(&c, (const unsigned char *)n, sizeof(n));

    uint8_t gid[4];
    zcl_write_u32_le(gid, (uint32_t)r->peer.gid);
    sha3_256_write(&c, gid, sizeof(gid));

    sha3_256_write(&c, r->property_id, MVAP_PROPERTY_ID_LEN);

    /* The canonical metaverse action receipt this confinement row COMMITS TO.
     * Inside the digest, so a row cannot later be re-pointed at a different
     * action; all-zero when the operation minted none, which is itself a
     * committed statement rather than an absent field. */
    sha3_256_write(&c, r->action_receipt_id, 32);

    if (v3) {
        uint8_t version[4], status_len[2];
        zcl_write_u32_le(version, r->receipt_version);
        size_t len = strnlen(r->money_snapshot_status,
                             sizeof(r->money_snapshot_status) - 1);
        zcl_write_u16_le(status_len, (uint16_t)len);
        sha3_256_write(&c, version, sizeof(version));
        sha3_256_write(&c, status_len, sizeof(status_len));
        sha3_256_write(&c,
                       (const unsigned char *)r->money_snapshot_status, len);
        sha3_256_write(&c, r->money_snapshot_root, 32);
    }

    const char *strs[3] = { r->principal, r->grant_id, r->detail };
    size_t caps[3] = { AGENT_PRINCIPAL_MAX, AGENT_GRANT_ID_MAX,
                       AGENT_RECEIPT_DETAIL_MAX };
    for (size_t i = 0; i < 3; i++) {
        size_t len = strnlen(strs[i], caps[i]);
        uint8_t lb[2];
        zcl_write_u16_le(lb, (uint16_t)len);
        sha3_256_write(&c, lb, 2);
        sha3_256_write(&c, (const unsigned char *)strs[i], len);
    }
    sha3_256_finalize(&c, out);
}

/* ── one canonical JSON line ────────────────────────────────────────────── */

static size_t receipt_render_line(const struct agent_receipt *r, char *out,
                                  size_t cap)
{
    char prev[65], id[65], sig[129], prop[65], action[65], money_root[65];
    zcl_hex_encode(r->prev, 32, prev);
    zcl_hex_encode(r->id, 32, id);
    zcl_hex_encode(r->sig, 64, sig);
    zcl_hex_encode(r->property_id, MVAP_PROPERTY_ID_LEN, prop);
    zcl_hex_encode(r->action_receipt_id, 32, action);
    zcl_hex_encode(r->money_snapshot_root, 32, money_root);

    int n = snprintf(out, cap,
        "{\"receipt_version\":%u,\"seq\":%llu,\"unix_ms\":%lld,"
        "\"prev\":\"%s\",\"id\":\"%s\","
        "\"sig\":\"%s\",\"verb\":\"%s\",\"request_id\":%u,\"status\":\"%s\","
        "\"status_code\":%d,\"value_zats\":%llu,\"property_id\":\"%s\","
        "\"action_receipt_id\":\"%s\",\"money_snapshot_status\":\"%s\","
        "\"money_snapshot_root\":\"%s\","
        "\"principal\":\"%s\",\"grant_id\":\"%s\",\"peer_pid\":%d,"
        "\"peer_uid\":%u,\"peer_gid\":%u,\"detail\":\"%s\"}\n",
        r->receipt_version, (unsigned long long)r->seq,
        (long long)r->unix_ms, prev, id, sig,
        mvap_verb_name(r->verb), r->request_id, mvap_status_name(r->status),
        r->status, (unsigned long long)r->value_zats, prop, action,
        r->money_snapshot_status, money_root,
        r->principal, r->grant_id, (int)r->peer.pid,
        (unsigned)r->peer.uid, (unsigned)r->peer.gid, r->detail);
    if (n < 0 || (size_t)n >= cap)
        return 0;
    return (size_t)n;
}

/* Rebuild a receipt from a rendered line. Returns false when a required field
 * is missing or malformed — counted as `malformed`, never silently skipped. */
static bool receipt_parse_line(const char *line, size_t len,
                               struct agent_receipt *out)
{
    struct json_value v;
    json_init(&v);
    if (!json_read(&v, line, len)) {
        json_free(&v);
        return false;
    }
    struct agent_receipt r = { 0 };
    bool ok = true;

    const struct json_value *version = json_get(&v, "receipt_version");
    r.receipt_version = version ? (uint32_t)json_get_int(version) : 2;
    if (r.receipt_version != 2 && r.receipt_version != 3)
        ok = false;
    r.seq        = (uint64_t)json_get_int(json_get(&v, "seq"));
    r.unix_ms    = json_get_int(json_get(&v, "unix_ms"));
    r.request_id = (uint32_t)json_get_int(json_get(&v, "request_id"));
    r.status     = (int32_t)json_get_int(json_get(&v, "status_code"));
    r.value_zats = (uint64_t)json_get_int(json_get(&v, "value_zats"));
    r.peer.pid   = (pid_t)json_get_int(json_get(&v, "peer_pid"));
    r.peer.uid   = (uid_t)json_get_int(json_get(&v, "peer_uid"));
    r.peer.gid   = (gid_t)json_get_int(json_get(&v, "peer_gid"));
    r.peer.valid = true;

    const char *verb = json_get_str(json_get(&v, "verb"));
    r.verb = mvap_verb_from_name(verb);
    if (r.verb == MVAP_VERB_NONE)
        ok = false;

    const char *s;
    if (!(s = json_get_str(json_get(&v, "prev"))) || !zcl_hex_decode(s, r.prev, 32))
        ok = false;
    if (!(s = json_get_str(json_get(&v, "id"))) || !zcl_hex_decode(s, r.id, 32))
        ok = false;
    if (!(s = json_get_str(json_get(&v, "sig"))) || !zcl_hex_decode(s, r.sig, 64))
        ok = false;
    if (!(s = json_get_str(json_get(&v, "property_id"))) ||
        !zcl_hex_decode(s, r.property_id, MVAP_PROPERTY_ID_LEN))
        ok = false;
    /* Required, not optional: a row that omits the binding is malformed, so a
     * verifier cannot be handed a truncated line and told the digest matched
     * because the missing field defaulted to zero. */
    if (!(s = json_get_str(json_get(&v, "action_receipt_id"))) ||
        !zcl_hex_decode(s, r.action_receipt_id, 32))
        ok = false;
    if (r.receipt_version >= 3) {
        s = json_get_str(json_get(&v, "money_snapshot_status"));
        if (!s || !s[0] || strlen(s) >= sizeof(r.money_snapshot_status))
            ok = false;
        else
            snprintf(r.money_snapshot_status,
                     sizeof(r.money_snapshot_status), "%s", s);
        if (!(s = json_get_str(json_get(&v, "money_snapshot_root"))) ||
            !zcl_hex_decode(s, r.money_snapshot_root, 32))
            ok = false;
    }

    if ((s = json_get_str(json_get(&v, "principal"))))
        snprintf(r.principal, sizeof(r.principal), "%s", s);
    if ((s = json_get_str(json_get(&v, "grant_id"))))
        snprintf(r.grant_id, sizeof(r.grant_id), "%s", s);
    if ((s = json_get_str(json_get(&v, "detail"))))
        snprintf(r.detail, sizeof(r.detail), "%s", s);

    json_free(&v);
    if (!ok)
        return false;
    *out = r;
    return true;
}

/* ── open ───────────────────────────────────────────────────────────────── */

/* Replay the existing log to recover (seq, head). A log whose last row is
 * unparseable stops the replay THERE rather than guessing: appending onto an
 * unknown head would silently start a second chain. */
static bool audit_replay_head(struct agent_audit_log *log)
{
    FILE *f = fopen(log->log_path, "re");
    if (!f) {
        if (errno == ENOENT) {
            log->seq = 0;
            memset(log->head, 0, 32);
            return true;
        }
        LOG_FAIL(AUDIT_TAG, "open %s failed: %s", log->log_path,
                 strerror(errno));
    }
    char line[AUDIT_LINE_MAX];
    uint64_t seq = 0;
    uint8_t head[32] = { 0 };
    while (fgets(line, sizeof(line), f)) {
        size_t n = strnlen(line, sizeof(line));
        if (n == 0 || line[n - 1] != '\n')
            break;                       /* truncated tail: stop here */
        struct agent_receipt r;
        if (!receipt_parse_line(line, n, &r))
            break;
        seq = r.seq;
        memcpy(head, r.id, 32);
    }
    (void)fclose(f);
    log->seq = seq;
    memcpy(log->head, head, 32);
    return true;
}

bool agent_audit_open(struct agent_audit_log *log, const char *dir)
{
    if (!log || !dir || !dir[0])
        LOG_FAIL(AUDIT_TAG, "null argument log=%p dir=%s", (void *)log,
                 dir ? dir : "(null)");

    memset(log, 0, sizeof(*log));
    snprintf(log->dir, sizeof(log->dir), "%s", dir);
    snprintf(log->log_path, sizeof(log->log_path), "%s/audit.log", dir);
    snprintf(log->pub_path, sizeof(log->pub_path), "%s/audit.pub", dir);

    uint8_t seed[32];
    if (!rng_fill(seed, sizeof(seed)))
        LOG_FAIL(AUDIT_TAG, "rng_fill refused: cannot mint an audit key");
    ed25519_keypair(log->pk, log->sk, seed);

    /* The public half is published so any later verifier needs only the
     * directory. A pre-existing key file means an earlier broker generation
     * signed part of this chain, so ADOPTing our fresh key would break
     * verification for those rows — keep the old one instead and refuse to
     * append under a key that cannot verify the head we just replayed. */
    char pub_hex[65];
    char *existing = NULL;
    size_t existing_size = 0;
    if (audit_read_stable(log->pub_path, 79, &existing, &existing_size)) {
        char buf[80] = { 0 };
        memcpy(buf, existing, existing_size);
        free(existing);
        bool got = existing_size != 0;
        size_t bl = strnlen(buf, sizeof(buf));
        while (bl && (buf[bl - 1] == '\n' || buf[bl - 1] == '\r'))
            buf[--bl] = '\0';
        if (!got || !zcl_hex_decode(buf, log->pk, 32))
            LOG_FAIL(AUDIT_TAG, "existing %s is not a 32-byte hex key",
                     log->pub_path);
        /* We hold no matching secret: this broker can VERIFY the old rows but
         * must not extend the chain under a key it cannot sign for. */
        memset(log->sk, 0, sizeof(log->sk));
        LOG_FAIL(AUDIT_TAG,
                 "%s already holds an audit key from a previous broker; "
                 "start a fresh broker dir rather than forking the chain",
                 log->pub_path);
    }

    zcl_hex_encode(log->pk, 32, pub_hex);
    struct platform_private_file pub;
    platform_private_file_init(&pub);
    if (!platform_private_file_create(log->pub_path, &pub))
        LOG_FAIL(AUDIT_TAG, "exclusive private create %s failed", log->pub_path);
    char pline[80];
    int pn = snprintf(pline, sizeof(pline), "%s\n", pub_hex);
    bool wrote = pn > 0 &&
        platform_private_file_write_at(&pub, pline, (size_t)pn, 0) &&
        platform_private_file_flush(&pub);
    platform_private_file_close(&pub);
    if (!wrote)
        LOG_FAIL(AUDIT_TAG, "durable write %s failed", log->pub_path);

    if (!audit_replay_head(log))
        LOG_FAIL(AUDIT_TAG, "could not replay %s to find the chain head",
                 log->log_path);

    log->open = true;
    return true;
}

/* ── append ─────────────────────────────────────────────────────────────── */

bool agent_audit_append(struct agent_audit_log *log, struct agent_receipt *r)
{
    if (!log || !r)
        LOG_FAIL(AUDIT_TAG, "null argument log=%p r=%p", (void *)log, (void *)r);
    if (!log->open)
        LOG_FAIL(AUDIT_TAG, "audit log %s is not open", log->log_path);

    if (r->receipt_version == 0) {
        r->receipt_version = 3;
        if (!r->money_snapshot_status[0])
            snprintf(r->money_snapshot_status,
                     sizeof(r->money_snapshot_status), "UNKNOWN");
    }
    r->seq     = log->seq + 1;
    r->unix_ms = clock_now_wall_ms();
    memcpy(r->prev, log->head, 32);
    receipt_digest(r, r->id);
    ed25519_sign(r->sig, r->id, 32, log->sk, log->pk);

    char line[AUDIT_LINE_MAX];
    size_t n = receipt_render_line(r, line, sizeof(line));
    if (n == 0)
        LOG_FAIL(AUDIT_TAG, "receipt seq=%llu does not fit a %d-byte line",
                 (unsigned long long)r->seq, AUDIT_LINE_MAX);

    struct platform_private_file file;
    platform_private_file_init(&file);
    if (!platform_private_file_open_locked_create(log->log_path, &file))
        LOG_FAIL(AUDIT_TAG, "open %s for exclusive append failed", log->log_path);
    uint64_t offset = 0;
    bool ok = platform_private_file_size(&file, &offset) &&
              platform_private_file_write_at(&file, line, n, offset) &&
              platform_private_file_flush(&file);
    platform_private_file_close(&file);
    if (!ok)
        LOG_FAIL(AUDIT_TAG, "append+durable flush to %s failed", log->log_path);

    log->seq = r->seq;
    memcpy(log->head, r->id, 32);
    return true;
}

/* ── verify ─────────────────────────────────────────────────────────────── */

static bool audit_read_pubkey(const char *dir, uint8_t pk[32])
{
    char path[448];
    snprintf(path, sizeof(path), "%s/audit.pub", dir);
    char *contents = NULL;
    size_t contents_size = 0;
    if (!audit_read_stable(path, 79, &contents, &contents_size))
        LOG_FAIL(AUDIT_TAG, "stable open of %s failed", path);
    char buf[80] = { 0 };
    memcpy(buf, contents, contents_size);
    free(contents);
    bool got = contents_size != 0;
    if (!got)
        LOG_FAIL(AUDIT_TAG, "%s is empty", path);
    size_t bl = strnlen(buf, sizeof(buf));
    while (bl && (buf[bl - 1] == '\n' || buf[bl - 1] == '\r'))
        buf[--bl] = '\0';
    if (!zcl_hex_decode(buf, pk, 32))
        LOG_FAIL(AUDIT_TAG, "%s is not 32-byte hex", path);
    return true;
}

bool agent_audit_verify_dir(const char *dir, struct agent_audit_verdict *out)
{
    if (!dir || !out)
        LOG_FAIL(AUDIT_TAG, "null argument dir=%s out=%p",
                 dir ? dir : "(null)", (void *)out);
    memset(out, 0, sizeof(*out));

    uint8_t pk[32];
    if (!audit_read_pubkey(dir, pk))
        LOG_FAIL(AUDIT_TAG, "no verifiable audit key in %s", dir);

    char path[448];
    snprintf(path, sizeof(path), "%s/audit.log", dir);
    char *contents = NULL;
    size_t contents_size = 0;
    if (!audit_read_stable(path, AUDIT_FILE_MAX, &contents, &contents_size))
        LOG_FAIL(AUDIT_TAG, "stable open of %s failed", path);

    uint8_t prev[32] = { 0 };
    uint64_t expect_seq = 1;
    char line[AUDIT_LINE_MAX];
    size_t offset = 0;
    while (offset < contents_size) {
        const char *newline = memchr(contents + offset, '\n',
                                     contents_size - offset);
        size_t n = newline ? (size_t)(newline - (contents + offset)) + 1 : 0;
        if (n == 0 || n >= sizeof(line)) {
            out->malformed++;
            break;
        }
        memcpy(line, contents + offset, n);
        line[n] = '\0';
        offset += n;
        struct agent_receipt r;
        if (!receipt_parse_line(line, n, &r)) {
            out->malformed++;
            continue;
        }
        out->rows++;

        /* Recompute the id from the row's own fields: an edited field lands
         * here, not in the signature check. */
        uint8_t want[32];
        receipt_digest(&r, want);
        if (memcmp(want, r.id, 32) != 0)
            out->chain_breaks++;
        else if (r.seq != expect_seq || memcmp(r.prev, prev, 32) != 0)
            out->chain_breaks++;

        if (!ed25519_verify(r.sig, r.id, 32, pk))
            out->bad_signatures++;

        memcpy(prev, r.id, 32);
        expect_seq = r.seq + 1;
    }
    free(contents);

    memcpy(out->head, prev, 32);
    out->ok = out->rows > 0 && out->chain_breaks == 0 &&
              out->bad_signatures == 0 && out->malformed == 0;
    return true;
}

/* ── render ─────────────────────────────────────────────────────────────── */

size_t agent_audit_render_json(const char *dir, size_t max, char *out,
                               size_t out_cap)
{
    if (!dir || !out || out_cap == 0)
        return 0;
    if (max == 0 || max > 200)
        max = 50;

    struct agent_audit_verdict v;
    bool verified = agent_audit_verify_dir(dir, &v);

    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    (void)json_push_kv_bool(&doc, "readable", verified);
    if (verified) {
        char head[65];
        zcl_hex_encode(v.head, 32, head);
        (void)json_push_kv_int(&doc, "rows", (int64_t)v.rows);
        (void)json_push_kv_int(&doc, "chain_breaks", (int64_t)v.chain_breaks);
        (void)json_push_kv_int(&doc, "bad_signatures",
                               (int64_t)v.bad_signatures);
        (void)json_push_kv_int(&doc, "malformed", (int64_t)v.malformed);
        (void)json_push_kv_bool(&doc, "tamper_evident_ok", v.ok);
        (void)json_push_kv_str(&doc, "head", head);
    } else {
        (void)json_push_kv_str(&doc, "reason",
                               "no audit.log/audit.pub in this directory");
    }

    /* Tail: re-read the file and keep the last `max` parsed rows. */
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    if (verified) {
        char path[448];
        snprintf(path, sizeof(path), "%s/audit.log", dir);
        FILE *f = fopen(path, "re");
        if (f) {
            /* Ring of the last `max` lines, so the render is bounded no matter
             * how long the log is. */
            static char ring[64][AUDIT_LINE_MAX];
            size_t cap = max < 64 ? max : 64;
            size_t count = 0, next = 0;
            char line[AUDIT_LINE_MAX];
            while (fgets(line, sizeof(line), f)) {
                snprintf(ring[next], AUDIT_LINE_MAX, "%s", line);
                next = (next + 1) % cap;
                count++;
            }
            (void)fclose(f);
            size_t have = count < cap ? count : cap;
            size_t start = count < cap ? 0 : next;
            for (size_t i = 0; i < have; i++) {
                const char *l = ring[(start + i) % cap];
                struct json_value one;
                json_init(&one);
                if (json_read(&one, l, strnlen(l, AUDIT_LINE_MAX)))
                    (void)json_push_back(&rows, &one);
                json_free(&one);
            }
        }
    }
    (void)json_push_kv(&doc, "receipts", &rows);
    json_free(&rows);

    size_t n = json_write(&doc, out, out_cap);
    json_free(&doc);
    return n;
}
