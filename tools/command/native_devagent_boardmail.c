/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: board-carried agent mail — the resident receiver's two carriage
 *          steps between enrolled boxes over the signed FLEET-scope board,
 *          and the admission of a row that arrived that way. No new
 *          transport: the node's own `fleet_board` RPC signs, stores and
 *          (through the paired fleet pull) carries every post.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. dev.agent.mail is host-local by contract: a post appends to THIS
 * box's outbox, and a pull reads one inbox file per peer, "written by
 * whatever transport delivers them". Until now that transport was an
 * out-of-tree shell loop copying row bytes over pinned SSH, which proved no
 * peer identity at all. Here the carrier is the board every node already
 * runs: a row travels as the verbatim text of a FLEET-scope note signed by
 * the sending box's node key, and the receiving box admits it only after
 * its own node confirms that exact post, text and signer, and after its
 * owner granted that sender's label to that enrolled box.
 *
 * NAMES. A box's receiver name IS its fleet roster name (`fleet machines`).
 * A row's `to` naming another roster box is what makes the row remote.
 *
 * EXPORT (after the receiver's answers are written). Complete outbox lines
 * past a byte cursor, at most BM_EXPORT_ROWS per beat. A row is exported
 * when its `to` is another enrolled box (recorded as "out <ref> <box>"), or
 * when its ref names a directive this box imported from a peer (so the
 * receiver's accept, its refusals and the worker's result, addressed to the
 * sender's label or to "*", travel back). Every other row is local mail and
 * never leaves the box: the design note said "every row not addressed to
 * this receiver", but that would publish all local-only mail to every
 * paired box and spend the 60-posts-per-10-minutes key quota on it.
 * The post is kind note, scope fleet, text = the row line exactly,
 * receipt "z23.mail.v1", ttl BM_TTL_S, and created_at = the row's own ts,
 * so a re-export after a crash signs the same bytes and is the same post id
 * (the store keeps one). A row whose ts is already older than the ttl is
 * never posted: it would be delivered late. A row too large for a board
 * note (BM_TEXT_MAX) is skipped with a log line; fleet.steer.send refuses
 * those before they are written. The cursor advances past a row only when
 * its post was stored or refused for a reason that cannot clear, so a node
 * that is down, busy or over quota delays the rest, never loses them.
 *
 * IMPORT (before intake). The node's `fleet_page` op: fleet posts in its
 * store's own arrival order after a cursor, under a per-process epoch (a new
 * epoch restarts at 0). A post is kept only when it is a z23.mail.v1 note,
 * its host is the signer of an enrolled box P other than this one, its text
 * is a well-formed row, and either the row's `to` is this receiver (then
 * "in <ref> P" is recorded) or its ref is one this box exported to P. It is
 * appended to <state>/mail/inbox.P.jsonl as the original row plus
 * "board_post":"<id>","board_signer":"<host hex>", unless a line beginning
 * with the identical original row is already in the file (the same post
 * re-gossiped, or a twin post of the same row). The match is on the whole
 * row, never on the post id alone: a line that merely NAMES a post id must
 * not stop the genuine row from arriving. The cursor is saved only after a
 * whole page was handled, so a crash replays the page and the dedupe keeps
 * one line. Correctness never depends on the cursor.
 *
 * ADMISSION (zcl_devagent_boardmail_admit). A row carrying a board field is
 * admitted only when ALL hold, in this order:
 *   1. both fields are 64 lowercase hex (else RECEIVE_PEER_UNSIGNED);
 *   2. this box's node answers show(board_post) (else
 *      RECEIVE_PEER_POST_MISSING, a DEFER: no marker, retried next beat);
 *      the post exists and is unexpired (else RECEIVE_PEER_POST_GONE:
 *      expired, reclaimed or never stored — never delivered late);
 *   3. the post is a fleet z23.mail.v1 note, its host is board_signer, and
 *      its text parses to exactly this row's fields (else
 *      RECEIVE_PEER_POST_MISMATCH: a forged or edited inbox line);
 *   4. a verified roster line names a box other than this one whose signer
 *      is board_signer (else RECEIVE_PEER_UNENROLLED);
 *   5. a live peer grant carries the row's `from` with the send scope for
 *      that box (zcl_fleet_steer_grant_peer_live, else
 *      RECEIVE_PEER_UNGRANTED).
 * sender_binding is not consulted on this path: only the sending box can
 * recompute it. A peer grant never admits an unsigned row, and a local
 * grant never admits a board row (see native_fleet.h).
 *
 * STATE. <state>/receive/boardmail.state (export_offset, import_epoch,
 * import_after; installed by rename) and <state>/receive/boardmail.refs
 * (append-only "out|in <ref> <box>" lines, newest BM_REFS_MAX read). Both
 * are the receiver's own owner-private files, never the mail dir, so a
 * writer of an inbox file cannot steer what this box exports.
 *
 * WHAT THIS DOES NOT PROVE. A verified post proves that an enrolled box's
 * node key signed these bytes. It does not prove the sender behind the
 * label on that box is who the label says: that is the sending box's own
 * grant check, which its steer send already made. Every paired fleet box
 * can read every FLEET post; there is no per-recipient confidentiality.
 *
 * PROCESS RULE. No spawn, no shell, no sleep. Local files plus loopback
 * calls to this box's own node RPC; nothing here dials a peer.
 */

#include "command/native_command.h"
#include "command/native_devagent.h"
#include "command/native_fleet.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "controllers/rpc_client.h"
#include "fleet_enrol.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define BM_LOG "dev.agent.boardmail"
#define BM_RECEIPT "z23.mail.v1"
#define BM_STATE_FILE "boardmail.state"
#define BM_REFS_FILE "boardmail.refs"
/* Owner decision: a carried row lives a week on the board. */
#define BM_TTL_S (7LL * 24 * 60 * 60)
/* The board's own signed text ceiling for a note (FLEET_BOARD_TEXT_MAX). */
#define BM_TEXT_MAX 2048u
#define BM_AGENT_MAX 64u
#define BM_EXPORT_ROWS 64u
#define BM_IMPORT_PAGES 4u
#define BM_PAGE_LIMIT 16
#define BM_REFS_MAX 1024u
#define BM_LINE_CAP 16384u
#define BM_PATH_CAP 4096u
#define BM_HEX 64u

/* ── small helpers ─────────────────────────────────────────────────────── */

static bool bm_hex64(const char *s)
{
    size_t i;
    if (!s || strlen(s) != BM_HEX)
        return false;
    for (i = 0; i < BM_HEX; i++) {
        if (!isxdigit((unsigned char)s[i]) || isupper((unsigned char)s[i]))
            return false;
    }
    return true;
}

static const char *bm_str(const struct json_value *o, const char *key)
{
    const struct json_value *v = json_get(o, key);
    return (v && v->type == JSON_STR && json_get_str(v)) ? json_get_str(v)
                                                         : "";
}

static long long bm_int(const struct json_value *o, const char *key,
                        long long dflt)
{
    const struct json_value *v = json_get(o, key);
    return (v && v->type == JSON_INT) ? (long long)json_get_int(v) : dflt;
}

/* Days since 1970-01-01 for a proleptic Gregorian date. */
static long long bm_days_from_civil(long long y, long long m, long long d)
{
    long long era, yoe, doy, doe;
    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

static bool bm_digits(const char *s, size_t n, long long *out)
{
    long long v = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        if (!isdigit((unsigned char)s[i]))
            return false;
        v = v * 10 + (s[i] - '0');
    }
    *out = v;
    return true;
}

/* The mail leaf's ts, exactly "YYYY-MM-DDTHH:MM:SSZ", as Unix seconds; -1
 * when it is not that shape. */
static long long bm_ts_unix(const char *ts)
{
    long long y, mo, d, h, mi, s;
    if (!ts || strlen(ts) != 20 || ts[4] != '-' || ts[7] != '-' ||
        ts[10] != 'T' || ts[13] != ':' || ts[16] != ':' || ts[19] != 'Z')
        return -1;
    if (!bm_digits(ts, 4, &y) || !bm_digits(ts + 5, 2, &mo) ||
        !bm_digits(ts + 8, 2, &d) || !bm_digits(ts + 11, 2, &h) ||
        !bm_digits(ts + 14, 2, &mi) || !bm_digits(ts + 17, 2, &s))
        return -1;
    if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 59)
        return -1;
    return bm_days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s;
}

/* ── one mail row, read from JSON (a board post's text or a pulled row) ── */

struct bm_row {
    long long seq;
    const char *ts, *from, *to, *kind, *body, *ref, *sender_binding;
};

static bool bm_row_from(const struct json_value *o, struct bm_row *r)
{
    const struct json_value *seq = json_get(o, "seq");
    memset(r, 0, sizeof(*r));
    if (!o || o->type != JSON_OBJ || !seq || seq->type != JSON_INT)
        return false;
    r->seq = (long long)json_get_int(seq);
    r->ts = bm_str(o, "ts");
    r->from = bm_str(o, "from");
    r->to = bm_str(o, "to");
    r->kind = bm_str(o, "kind");
    r->body = bm_str(o, "body");
    r->ref = bm_str(o, "ref");
    r->sender_binding = bm_str(o, "sender_binding");
    return r->ts[0] && r->to[0] && r->kind[0];
}

/* ── the roster: which enrolled box signs with which node key ──────────── */

struct bm_peer {
    char name[FLEET_ENROL_NAME_MAX + 1];
    uint8_t signer[FLEET_ENROL_PUBKEY_BYTES];
    uint8_t box[FLEET_ENROL_PUBKEY_BYTES];
};

struct bm_roster {
    struct bm_peer p[FLEET_ENROL_ROSTER_MAX];
    size_t n;
};

static void bm_roster_visit(const struct fleet_machine *m, void *user)
{
    static const uint8_t zero[FLEET_ENROL_PUBKEY_BYTES];
    struct bm_roster *r = user;
    struct bm_peer *p;
    /* A box that named no signing key cannot have signed a post. */
    if (r->n >= FLEET_ENROL_ROSTER_MAX ||
        memcmp(m->receipt.signer_pubkey, zero, sizeof(zero)) == 0)
        return;
    p = &r->p[r->n++];
    (void)snprintf(p->name, sizeof(p->name), "%s", m->receipt.invite.name);
    memcpy(p->signer, m->receipt.signer_pubkey, sizeof(p->signer));
    memcpy(p->box, m->receipt.box_pubkey, sizeof(p->box));
}

/* The operator key this box trusts: the one `fleet join` recorded, or, on
 * the manager, its own box key. Neither means no roster at all. */
static bool bm_operator(uint8_t out[FLEET_ENROL_PUBKEY_BYTES])
{
    uint8_t seed[FLEET_ENROL_SEED_BYTES];
    const char *why = NULL;
    bool joined = false, own = false;
    if (!fleet_enrol_operator_read(out, &joined, &why)) {
        LOG_WARN(BM_LOG, "fleet operator key unreadable: %s",
                 why ? why : "unknown");
        return false;
    }
    if (joined)
        return true;
    if (!fleet_enrol_key_load(seed, out, false, &own, &why))
        return false;
    memset(seed, 0, sizeof(seed));
    return own;
}

/* Every verified roster box with a signing key. Empty (never an error) on
 * a box that trusts no operator: such a box has no peers. */
static void bm_roster_load(struct bm_roster *r)
{
    uint8_t op[FLEET_ENROL_PUBKEY_BYTES];
    struct fleet_roster_scan scan;
    const char *why = NULL;
    memset(r, 0, sizeof(*r));
    if (!bm_operator(op))
        return;
    if (!fleet_roster_each(op, bm_roster_visit, r, &scan, &why)) {
        LOG_WARN(BM_LOG, "fleet roster unreadable: %s", why ? why : "unknown");
        r->n = 0;
    }
}

static const struct bm_peer *bm_by_name(const struct bm_roster *r,
                                        const char *name)
{
    size_t i;
    for (i = 0; name && i < r->n; i++) {
        if (strcmp(r->p[i].name, name) == 0)
            return &r->p[i];
    }
    return NULL;
}

static const struct bm_peer *bm_by_signer_hex(const struct bm_roster *r,
                                              const char *hex)
{
    uint8_t key[FLEET_ENROL_PUBKEY_BYTES];
    size_t i;
    if (!bm_hex64(hex) || !zcl_hex_decode(hex, key, sizeof(key)))
        return NULL;
    for (i = 0; i < r->n; i++) {
        if (memcmp(r->p[i].signer, key, sizeof(key)) == 0)
            return &r->p[i];
    }
    return NULL;
}

/* Is `to` another enrolled box, not this one? This box is the roster entry
 * whose box key is this box's own fleet key. */
bool zcl_devagent_boardmail_remote(const char *to)
{
    struct bm_roster *r;
    const struct bm_peer *p;
    uint8_t seed[FLEET_ENROL_SEED_BYTES], own[FLEET_ENROL_PUBKEY_BYTES];
    const char *why = NULL;
    bool present = false, remote;
    if (!to || !to[0] || strcmp(to, "*") == 0)
        return false;
    r = zcl_calloc(1, sizeof(*r), "boardmail.roster");
    if (!r) {
        LOG_WARN(BM_LOG, "cannot allocate the roster view");
        return false;
    }
    bm_roster_load(r);
    p = bm_by_name(r, to);
    if (!fleet_enrol_key_load(seed, own, false, &present, &why))
        present = false;
    memset(seed, 0, sizeof(seed));
    remote = p && !(present && memcmp(p->box, own, sizeof(own)) == 0);
    free(r);
    return remote;
}

/* ── the refs ledger: what went out to whom, what came in from whom ───── */

struct bm_ref {
    char dir; /* 'o' out, 'i' in */
    char ref[65];
    char peer[FLEET_ENROL_NAME_MAX + 1];
};

struct bm_refs {
    struct bm_ref r[BM_REFS_MAX];
    size_t n;
    char path[BM_PATH_CAP];
};

static bool bm_refs_has(const struct bm_refs *s, char dir, const char *ref,
                        const char *peer)
{
    size_t i;
    for (i = 0; ref && ref[0] && i < s->n; i++) {
        if (s->r[i].dir == dir && strcmp(s->r[i].ref, ref) == 0 &&
            (!peer || strcmp(s->r[i].peer, peer) == 0))
            return true;
    }
    return false;
}

/* The newest id wins a full ledger: the oldest entry is dropped. */
static void bm_refs_put(struct bm_refs *s, char dir, const char *ref,
                        const char *peer)
{
    struct bm_ref *e;
    if (s->n == BM_REFS_MAX) {
        memmove(&s->r[0], &s->r[1], (BM_REFS_MAX - 1) * sizeof(s->r[0]));
        s->n--;
    }
    e = &s->r[s->n++];
    e->dir = dir;
    (void)snprintf(e->ref, sizeof(e->ref), "%s", ref);
    (void)snprintf(e->peer, sizeof(e->peer), "%s", peer);
}

static void bm_refs_line(struct bm_refs *s, const char *line)
{
    char dir[4], ref[80], peer[40];
    if (sscanf(line, "%3s %79s %39s", dir, ref, peer) != 3)
        return;
    if ((strcmp(dir, "out") != 0 && strcmp(dir, "in") != 0) ||
        !zcl_devagent_name_ok(ref) || !fleet_enrol_name_valid(peer))
        return;
    bm_refs_put(s, dir[0] == 'o' ? 'o' : 'i', ref, peer);
}

static void bm_refs_load(struct bm_refs *s, const char *recvdir)
{
    char line[256];
    FILE *f;
    s->n = 0;
    (void)snprintf(s->path, sizeof(s->path), "%s/%s", recvdir, BM_REFS_FILE);
    f = fopen(s->path, "rb");
    if (!f)
        return;
    while (fgets(line, sizeof(line), f))
        bm_refs_line(s, line);
    (void)fclose(f);
}

/* Record one ref once. The ledger file is the receiver's own. */
static void bm_refs_add(struct bm_refs *s, char dir, const char *ref,
                        const char *peer)
{
    char line[160];
    FILE *f;
    int n;
    if (!zcl_devagent_name_ok(ref) || bm_refs_has(s, dir, ref, peer))
        return;
    n = snprintf(line, sizeof(line), "%s %s %s\n", dir == 'o' ? "out" : "in",
                 ref, peer);
    f = fopen(s->path, "ab");
    if (n <= 0 || (size_t)n >= sizeof(line) || !f ||
        fwrite(line, 1, (size_t)n, f) != (size_t)n) {
        LOG_WARN(BM_LOG, "cannot record ref %s in %s", ref, s->path);
        if (f)
            (void)fclose(f);
        return;
    }
    (void)fclose(f);
    bm_refs_put(s, dir, ref, peer);
}

/* ── carriage state ────────────────────────────────────────────────────── */

struct bm_state {
    long long export_offset;
    long long import_after;
    char import_epoch[40];
};

static void bm_state_path(const char *recvdir, char *out, size_t cap)
{
    (void)snprintf(out, cap, "%s/%s", recvdir, BM_STATE_FILE);
}

static void bm_state_line(const char *line, struct bm_state *st)
{
    if (strncmp(line, "export_offset=", 14) == 0)
        st->export_offset = strtoll(line + 14, NULL, 10);
    else if (strncmp(line, "import_after=", 13) == 0)
        st->import_after = strtoll(line + 13, NULL, 10);
    else if (strncmp(line, "import_epoch=", 13) == 0)
        (void)snprintf(st->import_epoch, sizeof(st->import_epoch), "%.32s",
                       line + 13);
}

static void bm_state_load(const char *recvdir, struct bm_state *st)
{
    char path[BM_PATH_CAP], line[128];
    FILE *f;
    memset(st, 0, sizeof(*st));
    bm_state_path(recvdir, path, sizeof(path));
    f = fopen(path, "rb");
    if (!f)
        return;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        bm_state_line(line, st);
    }
    (void)fclose(f);
    if (st->export_offset < 0)
        st->export_offset = 0;
    if (st->import_after < 0)
        st->import_after = 0;
}

/* Installed by rename, so a crash leaves the old cursors, never half. */
static void bm_state_save(const char *recvdir, const struct bm_state *st)
{
    char path[BM_PATH_CAP], tmp[BM_PATH_CAP + 8], text[256];
    FILE *f;
    int n = snprintf(text, sizeof(text),
                     "export_offset=%lld\nimport_epoch=%s\nimport_after=%lld\n",
                     st->export_offset, st->import_epoch, st->import_after);
    bm_state_path(recvdir, path, sizeof(path));
    (void)snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    f = fopen(tmp, "wb");
    if (n <= 0 || (size_t)n >= sizeof(text) || !f ||
        fwrite(text, 1, (size_t)n, f) != (size_t)n || fclose(f) != 0 ||
        rename(tmp, path) != 0) {
        LOG_WARN(BM_LOG, "cannot record the board mail cursors in %s", path);
        (void)remove(tmp);
    }
}

/* ── the node's fleet_board RPC ────────────────────────────────────────── */

enum bm_rpc { BM_RPC_OK, BM_RPC_REFUSED, BM_RPC_DOWN };

/* One `fleet_board` call in the board CLI's own envelope. DOWN when no node
 * answered at all (the client returns an error stub with no "ok"). */
static enum bm_rpc bm_call(const struct json_value *in, struct json_value *out)
{
    size_t n = json_write(in, NULL, 0);
    char *params = zcl_malloc(n + 3, "boardmail.params");
    char *raw;
    if (!params) {
        LOG_WARN(BM_LOG, "cannot allocate one board RPC request");
        return BM_RPC_DOWN;
    }
    params[0] = '[';
    (void)json_write(in, params + 1, n + 1);
    params[1 + n] = ']';
    params[2 + n] = '\0';
    zcl_native_bridge_ensure_rpc();
    raw = node_rpc_call("fleet_board", params);
    free(params);
    if (!raw || !json_read(out, raw, strlen(raw)) || out->type != JSON_OBJ ||
        !json_get(out, "ok")) {
        free(raw);
        return BM_RPC_DOWN;
    }
    free(raw);
    return json_get_bool(json_get(out, "ok")) ? BM_RPC_OK : BM_RPC_REFUSED;
}

/* ── export ────────────────────────────────────────────────────────────── */

enum bm_post { BM_POST_DONE, BM_POST_SKIP, BM_POST_RETRY };

/* Refusals that cannot clear by waiting: the post is malformed or would be
 * expired. Everything else (busy, over quota, store full, clock skew, no
 * node) is retried with the cursor held. */
static bool bm_refusal_final(const char *code)
{
    static const char *const finals[] = {
        "BAD_KIND", "MISSING_TEXT", "TEXT_TOO_LONG", "BAD_SCOPE", "BAD_ROOM",
        "BAD_TTL", "CREATED_AT_EXPIRED",
    };
    size_t i;
    for (i = 0; i < sizeof(finals) / sizeof(finals[0]); i++) {
        if (strcmp(code, finals[i]) == 0)
            return true;
    }
    return false;
}

static enum bm_post bm_post_row(const char *line, const struct bm_row *r,
                                long long now)
{
    struct json_value in, out;
    long long created = bm_ts_unix(r->ts);
    enum bm_rpc rc;
    enum bm_post verdict;
    if (created <= 0 || created + BM_TTL_S <= now) {
        LOG_WARN(BM_LOG, "row ref=%s seq=%lld is past its board ttl; "
                 "not carried late", r->ref, r->seq);
        return BM_POST_SKIP;
    }
    if (strlen(line) > BM_TEXT_MAX) {
        LOG_WARN(BM_LOG, "row ref=%s seq=%lld is over the %u-byte board "
                 "note; not carried", r->ref, r->seq, BM_TEXT_MAX);
        return BM_POST_SKIP;
    }
    json_init(&in);
    json_init(&out);
    json_set_object(&in);
    (void)json_push_kv_str(&in, "op", "post");
    (void)json_push_kv_str(&in, "kind", "note");
    (void)json_push_kv_str(&in, "scope", "fleet");
    (void)json_push_kv_str(&in, "text", line);
    (void)json_push_kv_str(&in, "agent",
                           strlen(r->from) <= BM_AGENT_MAX ? r->from : "");
    (void)json_push_kv_str(&in, "receipt", BM_RECEIPT);
    (void)json_push_kv_int(&in, "created_at", created);
    (void)json_push_kv_int(&in, "ttl", BM_TTL_S);
    rc = bm_call(&in, &out);
    verdict = rc == BM_RPC_OK ? BM_POST_DONE
              : rc == BM_RPC_REFUSED && bm_refusal_final(bm_str(&out, "code"))
                  ? BM_POST_SKIP
                  : BM_POST_RETRY;
    if (verdict != BM_POST_DONE)
        LOG_WARN(BM_LOG, "board post for ref=%s seq=%lld %s: %s", r->ref,
                 r->seq, verdict == BM_POST_SKIP ? "refused" : "deferred",
                 rc == BM_RPC_DOWN ? "no node answered" : bm_str(&out, "code"));
    json_free(&in);
    json_free(&out);
    return verdict;
}

/* Which box a row is carried for: `to` when it is another enrolled box,
 * the box a directive came from when the row answers it under that ref,
 * else NULL (local mail, never carried). *out_dir says whether to record
 * the row as sent to that box. */
static const char *bm_export_peer(const struct zcl_boardmail_ctx *c,
                                  const struct bm_roster *ro,
                                  const struct bm_refs *refs,
                                  const struct bm_row *r, bool *record)
{
    const struct bm_peer *p;
    size_t i;
    *record = false;
    if (strcmp(r->to, c->receiver) == 0)
        return NULL;
    p = bm_by_name(ro, r->to);
    if (p && strcmp(p->name, c->receiver) != 0) {
        *record = true;
        return p->name;
    }
    for (i = 0; r->ref[0] && i < refs->n; i++) {
        if (refs->r[i].dir == 'i' && strcmp(refs->r[i].ref, r->ref) == 0)
            return refs->r[i].peer;
    }
    return NULL;
}

/* One complete outbox line. False when the cursor must stay before it. */
static bool bm_export_line(const struct zcl_boardmail_ctx *c,
                           const struct bm_roster *ro, struct bm_refs *refs,
                           const char *line, struct rcv_beat_stats *st)
{
    struct json_value v;
    struct bm_row r;
    const char *peer;
    bool record = false, advance = true;
    json_init(&v);
    if (!json_read(&v, line, strlen(line)) || !bm_row_from(&v, &r) ||
        !(peer = bm_export_peer(c, ro, refs, &r, &record))) {
        json_free(&v);
        return true;
    }
    switch (bm_post_row(line, &r, (long long)platform_time_wall_time_t())) {
    case BM_POST_DONE:
        st->board_out++;
        if (record)
            bm_refs_add(refs, 'o', r.ref, peer);
        break;
    case BM_POST_SKIP:
        break;
    case BM_POST_RETRY:
        st->board_deferred++;
        advance = false;
        break;
    }
    json_free(&v);
    return advance;
}

/* Open the outbox at the cursor. A cursor past the end or not on a line
 * boundary means the file was replaced: start over, which re-signs the
 * same post ids and stores nothing twice. */
static FILE *bm_outbox_open(const char *maildir, long long *off)
{
    char path[BM_PATH_CAP];
    struct stat sb;
    FILE *f;
    (void)snprintf(path, sizeof(path), "%s/outbox.jsonl", maildir);
    f = fopen(path, "rb");
    if (!f)
        return NULL;
    if (fstat(fileno(f), &sb) != 0 || *off > (long long)sb.st_size ||
        (*off > 0 && (fseek(f, (long)(*off - 1), SEEK_SET) != 0 ||
                      fgetc(f) != '\n')))
        *off = 0;
    if (fseek(f, (long)*off, SEEK_SET) != 0) {
        (void)fclose(f);
        return NULL;
    }
    return f;
}

static void bm_export_walk(const struct zcl_boardmail_ctx *c,
                           const struct bm_roster *ro, struct bm_refs *refs,
                           struct bm_state *s, struct rcv_beat_stats *st)
{
    char *line = zcl_malloc(BM_LINE_CAP, "boardmail.line");
    FILE *f = line ? bm_outbox_open(c->maildir, &s->export_offset) : NULL;
    unsigned rows = 0;
    while (f && rows++ < BM_EXPORT_ROWS && fgets(line, BM_LINE_CAP, f)) {
        size_t len = strlen(line);
        /* A line still being written, or one longer than any row, stops
         * the walk / is stepped over whole. */
        if (len == 0 || line[len - 1] != '\n') {
            if (feof(f))
                break;
            while (fgets(line, BM_LINE_CAP, f) &&
                   line[strlen(line) - 1] != '\n')
                ;
            s->export_offset = (long long)ftell(f);
            continue;
        }
        line[len - 1] = '\0';
        if (!bm_export_line(c, ro, refs, line, st))
            break;
        s->export_offset += (long long)len;
    }
    if (f)
        (void)fclose(f);
    free(line);
}

/* ── import ────────────────────────────────────────────────────────────── */

/* Is this post (by id) or this exact original row already in the file? */
static bool bm_inbox_has(const char *path, const char *text)
{
    char *line = zcl_malloc(BM_LINE_CAP, "boardmail.inbox_line");
    size_t tlen = strlen(text);
    bool found = false;
    FILE *f;
    if (!line) {
        LOG_WARN(BM_LOG, "cannot allocate the inbox dedupe buffer");
        return true; /* never append what cannot be checked */
    }
    f = fopen(path, "rb");
    while (f && !found && fgets(line, BM_LINE_CAP, f)) {
        found = tlen > 1 && strncmp(line, text, tlen - 1) == 0 &&
                (line[tlen - 1] == ',' || line[tlen - 1] == '}');
    }
    if (f)
        (void)fclose(f);
    free(line);
    return found;
}

/* The original row with the two carrier fields appended: the row's text
 * ends in its closing brace, which the fields go in front of. */
static bool bm_inbox_append(const char *path, const char *text,
                            const char *id, const char *host)
{
    size_t tlen = strlen(text), cap = tlen + 200u, n;
    char *line;
    int fd, w;
    bool ok;
    if (tlen < 2 || text[tlen - 1] != '}')
        return false;
    line = zcl_malloc(cap, "boardmail.inbox_append");
    if (!line) {
        LOG_WARN(BM_LOG, "cannot allocate one inbox line");
        return false;
    }
    w = snprintf(line, cap, "%.*s,\"board_post\":\"%s\",\"board_signer\":"
                 "\"%s\"}\n", (int)(tlen - 1), text, id, host);
    n = w > 0 ? (size_t)w : 0u;
    fd = n > 0 && n < cap
             ? open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600)
             : -1;
    ok = fd >= 0 && write(fd, line, n) == (ssize_t)n;
    if (fd >= 0)
        (void)close(fd);
    if (!ok)
        LOG_WARN(BM_LOG, "cannot append a carried row to %s", path);
    free(line);
    return ok;
}

/* Is this post a carried mail row this box should keep, and from whom? */
static const struct bm_peer *bm_import_peer(const struct zcl_boardmail_ctx *c,
                                            const struct bm_roster *ro,
                                            const struct json_value *post)
{
    const struct bm_peer *p;
    if (strcmp(bm_str(post, "scope"), "fleet") != 0 ||
        strcmp(bm_str(post, "kind"), "note") != 0 ||
        strcmp(bm_str(post, "receipt"), BM_RECEIPT) != 0)
        return NULL;
    p = bm_by_signer_hex(ro, bm_str(post, "host"));
    return (p && strcmp(p->name, c->receiver) != 0) ? p : NULL;
}

static void bm_import_post(const struct zcl_boardmail_ctx *c,
                           const struct bm_roster *ro, struct bm_refs *refs,
                           const struct json_value *post,
                           struct rcv_beat_stats *st)
{
    const struct bm_peer *p = bm_import_peer(c, ro, post);
    const char *text = bm_str(post, "text"), *id = bm_str(post, "id");
    char path[BM_PATH_CAP];
    struct json_value v;
    struct bm_row r;
    bool mine;
    if (!p || !bm_hex64(id))
        return;
    json_init(&v);
    if (!json_read(&v, text, strlen(text)) || !bm_row_from(&v, &r)) {
        json_free(&v);
        return;
    }
    mine = strcmp(r.to, c->receiver) == 0;
    if (mine || bm_refs_has(refs, 'o', r.ref, p->name)) {
        (void)snprintf(path, sizeof(path), "%s/inbox.%s.jsonl", c->maildir,
                       p->name);
        if (mine)
            bm_refs_add(refs, 'i', r.ref, p->name);
        if (!bm_inbox_has(path, text) &&
            bm_inbox_append(path, text, id, bm_str(post, "host")))
            st->board_in++;
    }
    json_free(&v);
}

/* Adopt the answering node process's epoch. True when the cursor was in
 * another process's numbering and had to go back to 0 — a new process may
 * reuse the arrival number of a reclaimed row, so the page just read may
 * have started past rows this box never saw. */
static bool bm_import_epoch_moved(struct bm_state *s, const char *epoch)
{
    bool moved;
    if (strcmp(epoch, s->import_epoch) == 0)
        return false;
    (void)snprintf(s->import_epoch, sizeof(s->import_epoch), "%s", epoch);
    moved = s->import_after != 0;
    s->import_after = 0;
    return moved;
}

/* One fleet page after the cursor. False when no page could be read. */
static bool bm_import_page(const struct zcl_boardmail_ctx *c,
                           const struct bm_roster *ro, struct bm_refs *refs,
                           struct bm_state *s, bool *more,
                           struct rcv_beat_stats *st)
{
    struct json_value in, out;
    const struct json_value *posts;
    size_t i, n;
    bool ok;
    json_init(&in);
    json_init(&out);
    json_set_object(&in);
    (void)json_push_kv_str(&in, "op", "fleet_page");
    (void)json_push_kv_int(&in, "after", s->import_after);
    (void)json_push_kv_int(&in, "limit", BM_PAGE_LIMIT);
    ok = bm_call(&in, &out) == BM_RPC_OK;
    json_free(&in);
    if (ok && bm_import_epoch_moved(s, bm_str(&out, "epoch"))) {
        /* A page after a number the new process never handed out: ask
         * again from the start. */
        *more = true;
        json_free(&out);
        return true;
    }
    posts = ok ? json_get(&out, "posts") : NULL;
    n = (posts && posts->type == JSON_ARR) ? json_size(posts) : 0u;
    for (i = 0; i < n; i++)
        bm_import_post(c, ro, refs, json_at(posts, i), st);
    if (ok) {
        s->import_after = bm_int(&out, "scanned", s->import_after);
        *more = n >= (size_t)BM_PAGE_LIMIT;
    }
    json_free(&out);
    return ok;
}

/* ── the two beat steps ────────────────────────────────────────────────── */

struct bm_beat {
    struct bm_roster ro;
    struct bm_refs refs;
    struct bm_state s;
};

/* Load what one step needs. NULL when this box has no enrolled peer, which
 * makes both steps no-ops: nothing to carry to, nothing to trust. */
static struct bm_beat *bm_beat_open(const struct zcl_boardmail_ctx *c)
{
    struct bm_beat *b;
    if (!c || c->dry || !c->receiver || !c->recvdir || !c->maildir)
        return NULL;
    b = zcl_calloc(1, sizeof(*b), "boardmail.beat");
    if (!b) {
        LOG_WARN(BM_LOG, "cannot allocate one board mail step");
        return NULL;
    }
    bm_roster_load(&b->ro);
    if (b->ro.n == 0) {
        free(b);
        return NULL;
    }
    bm_refs_load(&b->refs, c->recvdir);
    bm_state_load(c->recvdir, &b->s);
    return b;
}

void zcl_devagent_boardmail_import(const struct zcl_boardmail_ctx *c,
                                   struct rcv_beat_stats *st)
{
    struct bm_beat *b = bm_beat_open(c);
    unsigned pages = 0;
    bool more = true;
    if (!b)
        return;
    while (more && pages++ < BM_IMPORT_PAGES) {
        more = false;
        if (!bm_import_page(c, &b->ro, &b->refs, &b->s, &more, st)) {
            st->board_deferred++;
            break;
        }
        bm_state_save(c->recvdir, &b->s);
    }
    free(b);
}

void zcl_devagent_boardmail_export(const struct zcl_boardmail_ctx *c,
                                   struct rcv_beat_stats *st)
{
    struct bm_beat *b = bm_beat_open(c);
    long long before;
    if (!b)
        return;
    /* Re-read the cursors: import may have saved them this beat. */
    bm_state_load(c->recvdir, &b->s);
    before = b->s.export_offset;
    bm_export_walk(c, &b->ro, &b->refs, &b->s, st);
    if (b->s.export_offset != before)
        bm_state_save(c->recvdir, &b->s);
    free(b);
}

/* ── admission ─────────────────────────────────────────────────────────── */

static void bm_decide(struct zcl_boardmail_decision *d,
                      enum zcl_boardmail_verdict v, const char *code,
                      const char *detail)
{
    d->verdict = v;
    d->code = code;
    (void)snprintf(d->detail, sizeof(d->detail), "%s", detail ? detail : "");
}

/* Does the post's text say exactly what the inbox row says? */
static bool bm_text_is_row(const char *text,
                           const struct zcl_boardmail_row *row)
{
    struct json_value v;
    struct bm_row r;
    bool same;
    json_init(&v);
    same = json_read(&v, text, strlen(text)) && bm_row_from(&v, &r) &&
           r.seq == row->seq && strcmp(r.ts, row->ts) == 0 &&
           strcmp(r.from, row->from) == 0 && strcmp(r.to, row->to) == 0 &&
           strcmp(r.kind, row->kind) == 0 &&
           strcmp(r.body, row->body) == 0 && strcmp(r.ref, row->ref) == 0 &&
           strcmp(r.sender_binding, row->sender_binding) == 0;
    json_free(&v);
    return same;
}

static void bm_admit_post(const struct json_value *post,
                          const struct zcl_boardmail_row *row,
                          struct zcl_boardmail_decision *d)
{
    long long expires = bm_int(post, "expires_at", 0);
    if (expires <= (long long)platform_time_wall_time_t()) {
        bm_decide(d, ZCL_BOARDMAIL_REFUSE, "RECEIVE_PEER_POST_GONE",
                  "post-expired");
        return;
    }
    if (strcmp(bm_str(post, "scope"), "fleet") != 0 ||
        strcmp(bm_str(post, "kind"), "note") != 0 ||
        strcmp(bm_str(post, "receipt"), BM_RECEIPT) != 0 ||
        strcmp(bm_str(post, "host"), row->board_signer) != 0 ||
        !bm_text_is_row(bm_str(post, "text"), row)) {
        bm_decide(d, ZCL_BOARDMAIL_REFUSE, "RECEIVE_PEER_POST_MISMATCH",
                  "post-does-not-carry-this-row");
        return;
    }
    bm_decide(d, ZCL_BOARDMAIL_ADMIT, NULL, NULL);
}

/* Steps 2 and 3: this box's own node vouches for the exact post. */
static void bm_admit_show(const struct zcl_boardmail_row *row,
                          struct zcl_boardmail_decision *d)
{
    struct json_value in, out;
    enum bm_rpc rc;
    json_init(&in);
    json_init(&out);
    json_set_object(&in);
    (void)json_push_kv_str(&in, "op", "show");
    (void)json_push_kv_str(&in, "id", row->board_post);
    rc = bm_call(&in, &out);
    if (rc == BM_RPC_OK)
        bm_admit_post(&out, row, d);
    else if (rc == BM_RPC_REFUSED &&
             strcmp(bm_str(&out, "code"), "NOT_FOUND") == 0)
        bm_decide(d, ZCL_BOARDMAIL_REFUSE, "RECEIVE_PEER_POST_GONE",
                  "post-not-held-here");
    else
        bm_decide(d, ZCL_BOARDMAIL_DEFER, "RECEIVE_PEER_POST_MISSING",
                  rc == BM_RPC_DOWN ? "no-node-answered"
                                    : bm_str(&out, "code"));
    json_free(&in);
    json_free(&out);
}

/* Steps 4 and 5: an enrolled box other than this one signed it, and the
 * owner granted this label to that box. */
static void bm_admit_peer(const struct zcl_boardmail_row *row,
                          const char *receiver,
                          struct zcl_boardmail_decision *d)
{
    struct bm_roster *ro = zcl_calloc(1, sizeof(*ro), "boardmail.admit");
    const struct bm_peer *p;
    const char *why;
    if (!ro) {
        bm_decide(d, ZCL_BOARDMAIL_DEFER, "RECEIVE_PEER_POST_MISSING",
                  "roster-view-unallocated");
        return;
    }
    bm_roster_load(ro);
    p = bm_by_signer_hex(ro, row->board_signer);
    if (!p || strcmp(p->name, receiver) == 0) {
        bm_decide(d, ZCL_BOARDMAIL_REFUSE, "RECEIVE_PEER_UNENROLLED",
                  "signer-is-no-enrolled-peer");
    } else {
        why = zcl_fleet_steer_grant_peer_live(row->from, p->name, "send");
        if (why)
            bm_decide(d, ZCL_BOARDMAIL_REFUSE, "RECEIVE_PEER_UNGRANTED", why);
        else
            bm_decide(d, ZCL_BOARDMAIL_ADMIT, NULL, p->name);
    }
    free(ro);
}

void zcl_devagent_boardmail_admit(const struct zcl_boardmail_row *row,
                                  const char *receiver,
                                  struct zcl_boardmail_decision *d)
{
    memset(d, 0, sizeof(*d));
    if (!row || !receiver || !bm_hex64(row->board_post) ||
        !bm_hex64(row->board_signer)) {
        bm_decide(d, ZCL_BOARDMAIL_REFUSE, "RECEIVE_PEER_UNSIGNED",
                  "board-fields-partial-or-malformed");
        return;
    }
    bm_admit_show(row, d);
    if (d->verdict != ZCL_BOARDMAIL_ADMIT)
        return;
    bm_admit_peer(row, receiver, d);
}
