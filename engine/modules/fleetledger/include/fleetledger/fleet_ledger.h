/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * fleet_ledger — the owner's private, replicated record of what the fleet
 * did and what it cost, held so that ANY machine can answer instantly.
 *
 * WHY THIS EXISTS
 * ---------------
 * The numbers that decide how this fleet is run — tokens, wall time, load,
 * disk, proofs landed — are today spread across per-host TSVs written by
 * shell (`usage.sh`, `exp.sh`) that only the host that wrote them can read.
 * Asking "what did the fleet spend this week" means logging into every box.
 * So the numbers are collected and never read, which is the same as not
 * collecting them.
 *
 * The fix is not a database. It is that every box holds every box's rows,
 * so the question is always answered locally, and the answer is a table
 * walk rather than a network call. That is what makes it instant, and it is
 * also what makes it private: nothing has to leave the owner's machines to
 * be queried.
 *
 * WHAT IT IS NOT
 * --------------
 * It is not a second append-only format. A per-box chain IS an
 * engine/modules/chainlog: SHA3-linked frames, a named first bad sequence
 * number, torn separated from tampered. This module adds the two things a
 * chainlog deliberately does not do — a TYPED row, and AUTHORSHIP.
 *
 * It is not consensus. Nothing here is on any chain, nothing votes, and a
 * row grants nothing. It is the owner's own bookkeeping about the owner's
 * own machines.
 *
 * It is not public. Rows move only between PAIRED peers over an established
 * Noise session, are stored owner-only under the datadir, and never reach a
 * public page, the interim board, or a log. A design question whose answer
 * would widen that is refused here rather than answered.
 *
 * IT HOLDS NO KEY MATERIAL
 * ------------------------
 * Same discipline as chainlog: signing takes a seed as an argument and the
 * handle never keeps it, so this module can never become the place a secret
 * quietly lives. Verification needs only the row's own box_id, which IS the
 * signer's Ed25519 public key.
 *
 * WHO A ROW IS FROM, AND WHY THAT KEY
 * -----------------------------------
 * `box_id` is the node-side ZCODE DHT online Ed25519 public key
 * (`<datadir>/zcode/dht/online_ed25519.key`, mode 0600). It is the key the
 * mesh pairing's delegation already binds to the peer's Noise static, so a
 * receiver can check a row's authorship against trust it ALREADY holds —
 * no new trust root, no new key file, and no second identity to revoke. The
 * dev proof signer is deliberately not used: it identifies a development
 * checkout's build receipts, not a machine on this mesh, and it is bound to
 * no peer link at all.
 *
 * The module never looks a pairing up. `zcl_fleet_ledger_replicate` is told
 * which box_id the caller's pairing row authorises, and refuses every row
 * that does not carry exactly that one (`ledger_peer_unpaired`). The
 * pairing lookup stays where the pairing rows live; the refusal stays here,
 * where the bytes are.
 *
 * NOTHING PARTIAL
 * ---------------
 * A batch is decoded, signature-checked and chain-checked in full BEFORE
 * one byte of it is appended. A forged, tampered, reordered or foreign row
 * anywhere in a batch refuses the whole batch and leaves the replica
 * exactly as it was.
 *
 * ON THE WIRE AND ON DISK (big-endian, no padding, no locale, no float)
 * --------------------------------------------------------------------
 *     0  version   u8   = ZCL_FLEET_ROW_VERSION
 *     1  kind      u8
 *     2  subject   u16
 *     4  pairs     u8   <= ZCL_FLEET_PAIRS_MAX
 *     5  note_len  u8   <= ZCL_FLEET_NOTE_MAX
 *     6  seq       u64  1-based, dense within its own chain
 *    14  ts_unix   i64
 *    22  box_id    [32] the signer's Ed25519 public key
 *    54  prev_hash [32] SHA3-256(domain || the whole previous row, sig and
 *                       all); 32 zero bytes for seq 1
 *    86  pairs     each { key u8, value i64 }, ascending by key, no repeats
 *   ...  note      note_len bytes, no NUL, no control bytes
 *   ...  sig       [64] Ed25519 over domain || every byte above
 *
 * The signature covers prev_hash and seq, so a row cannot be lifted out of
 * one chain and replayed into another, or moved within its own.
 */

#ifndef ZCL_FLEET_LEDGER_H
#define ZCL_FLEET_LEDGER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_FLEET_ROW_VERSION 1u
#define ZCL_FLEET_DOMAIN      "zcl.fleet_ledger_row.v1"

#define ZCL_FLEET_PAIRS_MAX   12u
#define ZCL_FLEET_NOTE_MAX    160u
#define ZCL_FLEET_ID_BYTES    32u
#define ZCL_FLEET_HASH_BYTES  32u
#define ZCL_FLEET_SIG_BYTES   64u
#define ZCL_FLEET_SEED_BYTES  32u

/* Fixed header, one encoded pair, and the largest a whole row can be. */
#define ZCL_FLEET_ROW_HEAD_BYTES 86u
#define ZCL_FLEET_ROW_PAIR_BYTES 9u
#define ZCL_FLEET_ROW_MAX_BYTES                                              \
    (ZCL_FLEET_ROW_HEAD_BYTES + ZCL_FLEET_PAIRS_MAX * ZCL_FLEET_ROW_PAIR_BYTES \
     + ZCL_FLEET_NOTE_MAX + ZCL_FLEET_SIG_BYTES)

/* Bounds on the whole store. Each is a refusal point, not a hope: a fleet
 * is the owner's own machines, and a store that would grow past these is
 * refused by name rather than allowed to consume the node. */
#define ZCL_FLEET_BOXES_MAX   32u   /* self plus paired peers */
#define ZCL_FLEET_BATCH_MAX   64u   /* rows one PULL answer may carry */

/* The index keeps this many UTC days of per-day detail per series. A day
 * that falls out of the window is folded into that series' remainder, which
 * keeps the whole-history total exact while the per-day answer is bounded.
 * A query asking for more days than this is refused by name rather than
 * answered from a window that does not contain them. */
#define ZCL_FLEET_INDEX_DAYS   32u
#define ZCL_FLEET_INDEX_CELLS  8192u  /* (box, kind, subject, day) cells */
#define ZCL_FLEET_INDEX_SERIES 2048u  /* (box, kind, subject) remainders */

/* Every way this refuses. There is no generic failure: a person asking why
 * a row was not stored can always be told which rule stopped it. The label
 * strings are the stable tokens the operator surfaces print. */
enum zcl_fleet_status {
    ZCL_FLEET_OK = 0,
    ZCL_FLEET_ARGUMENT,          /* a NULL, or a field over its bound */
    ZCL_FLEET_IO,                /* the file system, or the chainlog, said no */
    ZCL_FLEET_MALFORMED,         /* the bytes are not a row of this version */
    ZCL_FLEET_KIND_UNKNOWN,      /* a kind outside the closed enum */
    ZCL_FLEET_KIND_NOT_WRITABLE, /* a kind this build does not yet write */
    ZCL_FLEET_SUBJECT_UNKNOWN,   /* a subject outside its kind's closed set */
    ZCL_FLEET_VITAL_UNKNOWN,     /* kind=vitals, id not in the vitals catalog */
    ZCL_FLEET_PAIR_UNKNOWN,      /* a pair key outside the closed enum */
    ZCL_FLEET_CHAIN_BROKEN,      /* prev_hash does not continue the chain */
    ZCL_FLEET_SIG_INVALID,       /* the signature does not verify under box_id */
    ZCL_FLEET_PEER_UNPAIRED,     /* a row from a box this link may not carry */
    ZCL_FLEET_SEQUENCE,          /* sequence numbers are not dense */
    ZCL_FLEET_WINDOW,            /* more days asked for than the index keeps */
    ZCL_FLEET_FULL               /* a bounded table is full */
};

/* "ok", "ledger_chain_broken", "ledger_sig_invalid", "ledger_peer_unpaired",
 * "vital_unknown", ... — one stable token per value. */
const char *zcl_fleet_status_label(enum zcl_fleet_status s);

/* ── The closed vocabularies ─────────────────────────────────────────── */

/* Row kinds. The ledger is generic on purpose: the same chain, index and
 * sync later carry attestations and game rewards without a second store.
 * Only `usage`, `task` and `vitals` are writable in this build; the other
 * two are declared so their wire values are reserved now rather than
 * colliding with something later. */
enum zcl_fleet_kind {
    ZCL_FLEET_KIND_USAGE = 1,
    ZCL_FLEET_KIND_TASK = 2,
    ZCL_FLEET_KIND_ATTEST = 3,
    ZCL_FLEET_KIND_REWARD = 4,
    ZCL_FLEET_KIND_VITALS = 5
};

/* kind=usage: who was asked to do the work. */
enum zcl_fleet_provider {
    ZCL_FLEET_PROVIDER_CLAUDE_FABLE = 0,
    ZCL_FLEET_PROVIDER_CLAUDE_OPUS = 1,
    ZCL_FLEET_PROVIDER_CLAUDE_SONNET = 2,
    ZCL_FLEET_PROVIDER_CLAUDE_HAIKU = 3,
    ZCL_FLEET_PROVIDER_GROK = 4,
    ZCL_FLEET_PROVIDER_GLM = 5,
    ZCL_FLEET_PROVIDER_CODEX = 6,
    ZCL_FLEET_PROVIDER_MUSE = 7,
    ZCL_FLEET_PROVIDER_MAC = 8
};

/* kind=task: what the row is about. `quota` is how a weekly cap enters the
 * ledger — a cap is a row like any other, so calibration replicates with
 * everything else instead of living in one box's config. */
enum zcl_fleet_task_subject {
    ZCL_FLEET_TASK_QUOTA = 0,
    ZCL_FLEET_TASK_LANE = 1,
    ZCL_FLEET_TASK_UNIT = 2,
    ZCL_FLEET_TASK_TRAIN = 3,
    ZCL_FLEET_TASK_PROOF = 4
};

/* The closed set of things a value in a pair can BE. A pair key is what
 * makes two int64s from different boxes addable; an unnamed integer is not
 * a measurement. */
enum zcl_fleet_pair_key {
    ZCL_FLEET_PAIR_TOKENS_IN = 1,
    ZCL_FLEET_PAIR_TOKENS_OUT = 2,
    ZCL_FLEET_PAIR_TOKENS_CACHED = 3,
    ZCL_FLEET_PAIR_TOKENS_REASONING = 4,
    ZCL_FLEET_PAIR_WALL_MS = 5,
    ZCL_FLEET_PAIR_TURNS = 6,
    ZCL_FLEET_PAIR_TOOL_USES = 7,
    ZCL_FLEET_PAIR_COST_MICRO_USD = 8,
    ZCL_FLEET_PAIR_VALUE = 9,
    ZCL_FLEET_PAIR_COUNT = 10,
    ZCL_FLEET_PAIR_BYTES = 11,
    ZCL_FLEET_PAIR_LIMIT = 12
};
#define ZCL_FLEET_PAIR_KEY_MAX ZCL_FLEET_PAIR_LIMIT

/* A number the writer did not have is ABSENT, never zero: a task that
 * reported no cached tokens and a task whose provider does not report them
 * are different facts, and summing them as zero loses the difference. A
 * caller with nothing to say about a key omits the pair. */

const char *zcl_fleet_kind_name(uint8_t kind);
bool zcl_fleet_kind_from_name(const char *name, uint8_t *kind_out);
bool zcl_fleet_kind_writable(uint8_t kind);
/* The subject vocabulary is scoped BY KIND: subject 0 under `usage` is a
 * provider, under `task` it is a quota row, under `vitals` it is the first
 * id in the vitals catalog. There is no cross-kind subject space. */
const char *zcl_fleet_subject_name(uint8_t kind, uint16_t subject);
bool zcl_fleet_subject_from_name(uint8_t kind, const char *name,
                                 uint16_t *subject_out);
const char *zcl_fleet_pair_name(uint8_t key);
bool zcl_fleet_pair_from_name(const char *name, uint8_t *key_out);

/* The vitals catalog, from engine/composition/fleet_vitals.def. Index is
 * the subject value on the wire, so the order in that file is identity. */
size_t zcl_fleet_vital_count(void);
const char *zcl_fleet_vital_id(uint16_t index);
const char *zcl_fleet_vital_unit(uint16_t index);
const char *zcl_fleet_vital_agg(uint16_t index);
int64_t zcl_fleet_vital_cadence_s(uint16_t index);

/* ── A row ───────────────────────────────────────────────────────────── */

struct zcl_fleet_pair {
    uint8_t key;   /* enum zcl_fleet_pair_key */
    int64_t value;
};

struct zcl_fleet_row {
    uint64_t seq;
    int64_t ts_unix;
    uint8_t box_id[ZCL_FLEET_ID_BYTES];
    uint8_t kind;
    uint16_t subject;
    uint8_t pair_count;
    uint8_t note_len;
    struct zcl_fleet_pair pair[ZCL_FLEET_PAIRS_MAX];
    char note[ZCL_FLEET_NOTE_MAX];
    uint8_t prev_hash[ZCL_FLEET_HASH_BYTES];
    uint8_t sig[ZCL_FLEET_SIG_BYTES];
};

/* Shape and vocabulary only — no crypto, no I/O. This is the check that
 * says "these fields could be a row", and it is run on every path. */
enum zcl_fleet_status zcl_fleet_row_validate(const struct zcl_fleet_row *row);

/* Canonical bytes. Returns the length written, or 0 when the row is invalid
 * or the buffer is too small; there is exactly one encoding of a row. */
size_t zcl_fleet_row_encode(const struct zcl_fleet_row *row, uint8_t *out,
                            size_t cap);

/* Decode one row from the front of `in`. `*consumed` receives its length,
 * so a batch is decoded by walking. Validates shape and vocabulary; does
 * NOT check the signature or the chain. */
enum zcl_fleet_status zcl_fleet_row_decode(const uint8_t *in, size_t len,
                                           struct zcl_fleet_row *out,
                                           size_t *consumed);

/* SHA3-256(domain || encoded row including its signature) — what the NEXT
 * row's prev_hash must equal. */
void zcl_fleet_row_hash(const uint8_t *encoded, size_t len,
                        uint8_t out[ZCL_FLEET_HASH_BYTES]);

/* Fill row->sig. The seed is used and forgotten: it is not stored anywhere
 * and the row's box_id must be the public key that seed derives. */
enum zcl_fleet_status zcl_fleet_row_sign(
    struct zcl_fleet_row *row, const uint8_t seed[ZCL_FLEET_SEED_BYTES]);

/* Verify the signature under the row's own box_id. */
enum zcl_fleet_status zcl_fleet_row_verify(const struct zcl_fleet_row *row);

/* ── The ledger ──────────────────────────────────────────────────────── */

/* What an open found, filled on success AND on refusal — "it refused"
 * without saying where is not a diagnosis. */
struct zcl_fleet_report {
    enum zcl_fleet_status status;
    uint64_t rows;           /* rows loaded into the index */
    uint64_t boxes;          /* chains found, self included */
    uint64_t indexed;        /* rows that landed in a per-day cell */
    uint64_t folded;         /* rows outside the day window, in remainders */
    uint8_t bad_box[ZCL_FLEET_ID_BYTES]; /* whose chain refused; zero if none */
    uint64_t first_bad_seq;  /* 0 when nothing was bad */
    uint64_t load_us;        /* wall cost of reading every chain */
};

struct zcl_fleet_ledger;

/* Open `<dir>` (creating it owner-only when absent), read every chain in it
 * once, and build the index. The chainlogs are CLOSED again before this
 * returns: a handle holds no file and no lock, because the node's service
 * and an operator's command are two processes over one store and neither
 * may be able to shut the other out. `self_box_id` may be NULL for a
 * read-only user that has no identity of its own.
 *
 * A chain that refuses is not skipped and not repaired: the refusal is the
 * evidence that something was altered, so the open fails and names the box
 * and the sequence number. */
struct zcl_fleet_ledger *zcl_fleet_ledger_open(
    const char *dir, const uint8_t self_box_id[ZCL_FLEET_ID_BYTES],
    struct zcl_fleet_report *report);

void zcl_fleet_ledger_close(struct zcl_fleet_ledger *ledger);

/* Append one row to this box's own chain, signed with `seed`. Re-reads the
 * chain's tail under the chainlog's exclusive lock before composing the
 * row, so two processes appending at once produce two dense rows rather
 * than two rows claiming the same sequence number. Returns after the
 * chainlog's two fsyncs. */
enum zcl_fleet_status zcl_fleet_ledger_append(
    struct zcl_fleet_ledger *ledger, uint8_t kind, uint16_t subject,
    const struct zcl_fleet_pair *pairs, size_t pair_count, const char *note,
    const uint8_t seed[ZCL_FLEET_SEED_BYTES], uint64_t *out_seq);

/* The highest sequence number held for `box_id`, or 0 for a box with no
 * chain here yet. This is the `since_seq` a PULL asks with. */
uint64_t zcl_fleet_ledger_peer_seq(const struct zcl_fleet_ledger *ledger,
                                   const uint8_t box_id[ZCL_FLEET_ID_BYTES]);

/* Encode this box's own rows after `since_seq` into `out`, stopping at the
 * buffer, at ZCL_FLEET_BATCH_MAX rows, or at the end of the chain. This is
 * what a PULL is answered with. */
enum zcl_fleet_status zcl_fleet_ledger_read_since(
    struct zcl_fleet_ledger *ledger, const uint8_t box_id[ZCL_FLEET_ID_BYTES],
    uint64_t since_seq, uint8_t *out, size_t cap, size_t *len,
    uint64_t *last_seq);

/* Verify and append a batch to `peer_box_id`'s replica. ALL OR NOTHING: the
 * whole batch is decoded, every signature checked under `peer_box_id`, and
 * the chain continuity checked against the replica's current head and
 * across the batch, BEFORE anything is written. Any row whose box_id is not
 * `peer_box_id` refuses the batch as `ledger_peer_unpaired` — a paired link
 * carries that peer's rows and nobody else's, so a peer cannot use its own
 * authorised link to plant rows attributed to a third machine.
 *
 * Rows at or below the replica's head are dropped as already held, which is
 * what makes a second pull a no-op rather than a refusal. */
enum zcl_fleet_status zcl_fleet_ledger_replicate(
    struct zcl_fleet_ledger *ledger,
    const uint8_t peer_box_id[ZCL_FLEET_ID_BYTES], const uint8_t *rows,
    size_t len, size_t *accepted);

/* ── Querying ────────────────────────────────────────────────────────── */

/* What one box's chain looks like from here. `age_s` is how old the newest
 * row is: a replica answers instantly, and this is how it stays honest
 * about the fact that instantly is not the same as currently. */
struct zcl_fleet_box_status {
    uint8_t box_id[ZCL_FLEET_ID_BYTES];
    bool is_self;
    uint64_t rows;
    uint64_t last_seq;
    int64_t last_ts;
};

size_t zcl_fleet_ledger_boxes(const struct zcl_fleet_ledger *ledger,
                              struct zcl_fleet_box_status *out, size_t cap);

struct zcl_fleet_query {
    uint8_t kind;          /* required */
    bool have_subject;
    uint16_t subject;
    bool have_box;
    uint8_t box_id[ZCL_FLEET_ID_BYTES];
    uint32_t days;         /* 1..ZCL_FLEET_INDEX_DAYS, ending at `today` */
    int64_t now_unix;      /* the caller's clock; the module reads none */
};

/* One (box, subject) answer over the asked-for window, with the pair sums
 * added by key. `absent[k]` distinguishes "summed to zero" from "no row
 * ever carried this key", which is the whole point of the -1/absent rule. */
struct zcl_fleet_bucket {
    uint8_t box_id[ZCL_FLEET_ID_BYTES];
    uint16_t subject;
    uint64_t rows;
    int64_t last_ts;
    int64_t sum[ZCL_FLEET_PAIR_KEY_MAX + 1];
    bool present[ZCL_FLEET_PAIR_KEY_MAX + 1];
};

/* Answer from the in-memory index alone: no file is opened, no lock is
 * taken and no peer is asked. `*index_us` receives what the walk cost, so
 * the claim that this is instant is measured rather than asserted. */
enum zcl_fleet_status zcl_fleet_ledger_query(
    const struct zcl_fleet_ledger *ledger, const struct zcl_fleet_query *query,
    struct zcl_fleet_bucket *out, size_t cap, size_t *count,
    uint64_t *index_us);

/* Rows the index could not give a per-day cell to because the cell pool was
 * full. They are still counted in their series remainder, so a total stays
 * exact; a non-zero value here means a per-DAY answer is incomplete and the
 * operator surfaces say so rather than printing a smaller number as if it
 * were the whole one. */
uint64_t zcl_fleet_ledger_index_overflow(const struct zcl_fleet_ledger *l);

/* The UTC day number a timestamp falls in — the index's bucket key, exposed
 * because a caller rendering a table needs the same arithmetic. */
uint32_t zcl_fleet_day_of(int64_t ts_unix);

#endif /* ZCL_FLEET_LEDGER_H */
