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
 * Same discipline as chainlog: signing takes the online key's seed as an
 * argument and the handle never keeps it, so this module can never become
 * the place a secret quietly lives. Verification needs only the row's own
 * `signer` field, which is a public key.
 *
 * WHO A ROW IS FROM, AND WHY THOSE KEYS
 * -------------------------------------
 * There is ONE node identity, and it is the one boot_mesh_pairing already
 * consumes: `struct vcs_zcode_dht_delegation`. A row carries both halves of
 * it, because they answer different questions.
 *
 *   box_id — the delegation's `doc.master_pubkey`. WHICH MACHINE this is.
 *            It survives an online-key rotation and a renewal, so a box's
 *            history stays one history across both.
 *   signer — the delegation's `online_pubkey`. WHICH KEY signed this row.
 *            The short-lived key is what actually signs, so a compromise of
 *            a running node does not reach the master.
 *
 * The delegation document is what binds them, and it binds the peer's Noise
 * static in the same breath — so the machine that sent a row over a Noise
 * session, the key that signed it and the identity it claims are one fact,
 * checked once, in the layer that holds delegations. The dev proof signer
 * is deliberately never used: it identifies a development checkout's build
 * receipts, is bound to no peer link, and a checkout that proved a build is
 * not a machine on this mesh.
 *
 * This module verifies the signature under `signer` and NOTHING ELSE about
 * identity: it never opens a key file, never derives a key, and never looks
 * a delegation or a pairing up. `zcl_fleet_ledger_replicate` is TOLD the
 * box_id and the signer the caller's verified delegation authorises, and
 * refuses any row that does not carry exactly those. That keeps the
 * delegation's own lifecycle — where an EXPIRED document is a distinct and
 * expected outcome, never confused with a bad signature — in the one place
 * that can judge it, and keeps the refusal here, where the bytes are.
 *
 * MERGE CLASS IS DECLARED, AND ENFORCED ON REPLAY
 * -----------------------------------------------
 * Two boxes' rows about the same subject and day are combined by a rule
 * declared in the schema, never guessed at read time:
 *
 *   IMMUTABLE  — seq, ts_unix, box_id, signer, kind, subject, prev_hash and
 *                the signature. Nothing ever restates them; a row that
 *                disagrees is not a merge, it is a different row.
 *   COUNTER    — a per-box, add-only quantity; reading is a sum. This is
 *                what tokens_in, tokens_out, tokens_cached,
 *                tokens_reasoning, wall_ms and turns are, and it is why two
 *                boxes' spend can be added at all.
 *   LWW        — the latest statement wins, ordered by (seq, box_id) and
 *                NEVER by wall time. A clock that is wrong or adjusted must
 *                not be able to decide which of two facts is newer, so the
 *                chain's own order decides. `note` is LWW, and so is a
 *                gauge: a load average is the value AT a moment, and adding
 *                two of them produces a number that measures nothing.
 *   OWNER_ONLY — the default for anything not named above: only the writer
 *                box may state it. A row inside an authorised batch that
 *                claims a different writer refuses as `ledger_not_owner`.
 *
 * The index is fed in chain order and only ever in chain order, which is
 * what makes "the latest statement" well defined without a clock.
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
 * The fixed header carries everything IMMUTABLE, seq and ts_unix included,
 * so a reader knows when and where a row belongs before it has looked at
 * one byte of variable-length payload.
 *
 *     0  version   u8   = ZCL_FLEET_ROW_VERSION
 *     1  kind      u8
 *     2  subject   u16
 *     4  pairs     u8   <= ZCL_FLEET_PAIRS_MAX
 *     5  note_len  u8   <= ZCL_FLEET_NOTE_MAX
 *     6  seq       u64  1-based, dense within its own chain
 *    14  ts_unix   i64  the writer's statement of WHEN, and never an order
 *    22  box_id    [32] the delegation's master public key: which machine
 *    54  signer    [32] the delegation's online public key: which key signed
 *    86  prev_hash [32] SHA3-256(domain || the whole previous row, sig and
 *                       all); 32 zero bytes for seq 1
 *   118  pairs     each { key u8, value i64 }, ascending by key, no repeats
 *   ...  note      note_len bytes, no NUL, no control bytes
 *   ...  sig       [64] Ed25519 over domain || every byte above, under
 *                       `signer`
 *
 * The signature covers prev_hash and seq, so a row cannot be lifted out of
 * one chain and replayed into another, or moved within its own. It covers
 * box_id and signer together, so a row cannot be re-attributed to another
 * machine or another key without breaking it.
 */

#ifndef ZCL_FLEET_LEDGER_H
#define ZCL_FLEET_LEDGER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_FLEET_ROW_VERSION 1u
#define ZCL_FLEET_DOMAIN      "zcl.fleet_ledger_row.v1"

#define ZCL_FLEET_PAIRS_MAX   16u
#define ZCL_FLEET_NOTE_MAX    160u
#define ZCL_FLEET_ID_BYTES    32u
#define ZCL_FLEET_HASH_BYTES  32u
#define ZCL_FLEET_SIG_BYTES   64u
#define ZCL_FLEET_SEED_BYTES  32u

/* Fixed header, one encoded pair, and the largest a whole row can be. */
#define ZCL_FLEET_ROW_HEAD_BYTES 118u
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
    ZCL_FLEET_SIG_INVALID,       /* the signature does not verify under signer */
    ZCL_FLEET_PEER_UNPAIRED,     /* a row from a box this link may not carry */
    ZCL_FLEET_NOT_OWNER,         /* a field only its writer box may state */
    /* The peer's delegation document expired. Kept distinct from a bad
     * signature on purpose: an expiry is expected lifecycle and the answer
     * is a renewal, while a signature failure is tampering or corruption
     * and the answer is never to accept the row. Collapsing the two would
     * make an ordinary renewal look like an attack and an attack look like
     * an ordinary renewal. */
    ZCL_FLEET_DELEGATION_EXPIRED,
    ZCL_FLEET_SEQUENCE,          /* sequence numbers are not dense */
    ZCL_FLEET_WINDOW,            /* more days asked for than the index keeps */
    ZCL_FLEET_FULL,              /* a bounded table is full */
    /* An experiment enum was missing, was `unknown`, or was not in that
     * field's closed vocabulary. Named so a caller can say which field
     * refused rather than collapsing it into a generic malformed row. */
    ZCL_FLEET_EXPERIMENT_ENUM
};

/* "ok", "ledger_chain_broken", "ledger_sig_invalid", "ledger_peer_unpaired",
 * "vital_unknown", ... — one stable token per value. */
const char *zcl_fleet_status_label(enum zcl_fleet_status s);

/* ── The closed vocabularies ─────────────────────────────────────────── */

/* Row kinds. The ledger is generic on purpose: the same chain, index and
 * sync later carry attestations and game rewards without a second store.
 * Only `usage`, `task`, `vitals` and `experiment` are writable in this
 * build; `attest` and `reward` are declared so their wire values are
 * reserved now rather than colliding with something later. */
enum zcl_fleet_kind {
    ZCL_FLEET_KIND_USAGE = 1,
    ZCL_FLEET_KIND_TASK = 2,
    ZCL_FLEET_KIND_ATTEST = 3,
    ZCL_FLEET_KIND_REWARD = 4,
    ZCL_FLEET_KIND_VITALS = 5,
    ZCL_FLEET_KIND_EXPERIMENT = 6
};

/* kind=experiment: the wire subject is the phase. The task_id lives in
 * `note` — a uint16 cannot hold it, and two rows of one delegation link
 * by that note. */
enum zcl_fleet_experiment_phase {
    ZCL_FLEET_EXPERIMENT_PREDICT = 0,
    ZCL_FLEET_EXPERIMENT_RESULT = 1
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
    ZCL_FLEET_PAIR_LIMIT = 12,
    ZCL_FLEET_PAIR_WALL_S = 13,
    ZCL_FLEET_PAIR_LINES_ADDED = 14,
    ZCL_FLEET_PAIR_LINES_REMOVED = 15,
    ZCL_FLEET_PAIR_DEFECTS = 16,
    ZCL_FLEET_PAIR_TASK_CLASS = 17,
    ZCL_FLEET_PAIR_HARNESS = 18,
    ZCL_FLEET_PAIR_OUTCOME = 19,
    ZCL_FLEET_PAIR_MODEL = 20,
    ZCL_FLEET_PAIR_EFFORT = 21
};
#define ZCL_FLEET_PAIR_KEY_MAX ZCL_FLEET_PAIR_EFFORT

/* A number the writer did not have is ABSENT, never zero: a task that
 * reported no cached tokens and a task whose provider does not report them
 * are different facts, and summing them as zero loses the difference. A
 * caller with nothing to say about a key omits the pair.
 *
 * Absence is carried as a STATE BYTE beside every value rather than as a
 * sentinel inside it, because every sentinel is a number somebody will one
 * day legitimately measure. This is kpi_ledger's rule, and it is the field
 * that makes the distinction survive being written down instead of merely
 * being rendered. */
enum zcl_fleet_field_state {
    ZCL_FLEET_FIELD_ABSENT = 0,  /* no row ever carried this key */
    ZCL_FLEET_FIELD_PRESENT = 1  /* at least one did; the value is real */
};

/* How two statements about the same (box, kind, subject, day) combine. It
 * is declared here, per pair key, and applied on replay — never decided at
 * read time by whichever caller happened to ask. */
enum zcl_fleet_merge {
    ZCL_FLEET_MERGE_IMMUTABLE = 0,  /* stated once; never restated */
    ZCL_FLEET_MERGE_COUNTER = 1,    /* per-box, add-only; reading is a sum */
    ZCL_FLEET_MERGE_LWW = 2,        /* latest by (seq, box_id), never by clock */
    ZCL_FLEET_MERGE_OWNER_ONLY = 3  /* only the writer box may state it */
};

const char *zcl_fleet_merge_name(enum zcl_fleet_merge merge);

/* The class of one pair key, in the context of the row that carries it. A
 * `vitals` row's `value` takes its class from the catalog's own aggregation
 * — a `sum` metric is a COUNTER and a `gauge` is LWW — because the catalog
 * is where that was already declared and a second declaration here could
 * only ever disagree with it. */
enum zcl_fleet_merge zcl_fleet_pair_merge(uint8_t kind, uint16_t subject,
                                          uint8_t key);

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

/* Experiment closed vocabularies. `unknown` is a named member so a
 * refusal can say the word; it is never stored. A name that is not in
 * the field's table is the same refusal. `field` is the input key
 * (`task_class`, `harness`, `outcome`, `model`, `effort`). */
bool zcl_fleet_experiment_enum_from_name(const char *field, const char *name,
                                         uint8_t *out);
const char *zcl_fleet_experiment_enum_name(const char *field, uint8_t value);
bool zcl_fleet_experiment_enum_stored(const char *field, uint8_t value);
bool zcl_fleet_experiment_enum_key(uint8_t key);
bool zcl_fleet_experiment_enum_pair_ok(uint8_t key, int64_t value);

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
    uint8_t box_id[ZCL_FLEET_ID_BYTES]; /* delegation doc.master_pubkey */
    uint8_t signer[ZCL_FLEET_ID_BYTES]; /* delegation online_pubkey */
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

/* Fill row->sig with the online key. The seed is used and forgotten: it is
 * not stored anywhere, and the row's `signer` must be the public key that
 * seed derives — a row signed by a key it does not name would verify
 * nowhere and would be discovered only by the peer that received it. */
enum zcl_fleet_status zcl_fleet_row_sign(
    struct zcl_fleet_row *row, const uint8_t seed[ZCL_FLEET_SEED_BYTES]);

/* Verify the signature under the row's own `signer`. This says the bytes
 * are intact and were signed by that key. Whether that key is the online
 * key `box_id` delegated is the caller's question, answered from the
 * delegation document; this module has no opinion on it. */
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
    const uint8_t self_signer[ZCL_FLEET_ID_BYTES],
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
 * whole batch is decoded, every signature checked, every row's authorship
 * checked, and the chain continuity checked against the replica's current
 * head and across the batch, BEFORE anything is written.
 *
 * `peer_box_id` and `peer_signer` are what the caller's VERIFIED delegation
 * authorises for this link. A row naming a different box refuses the batch
 * as `ledger_not_owner` — a paired link carries that peer's own rows and
 * nobody else's, so a peer cannot use its own authorised link to plant rows
 * attributed to a third machine. A row naming a different signer refuses as
 * `ledger_peer_unpaired`: the key that signed it is not the online key this
 * box's delegation delegates, whatever the signature says.
 *
 * Rows at or below the replica's head are dropped as already held, which is
 * what makes a second pull a no-op rather than a refusal. */
enum zcl_fleet_status zcl_fleet_ledger_replicate(
    struct zcl_fleet_ledger *ledger,
    const uint8_t peer_box_id[ZCL_FLEET_ID_BYTES],
    const uint8_t peer_signer[ZCL_FLEET_ID_BYTES], const uint8_t *rows,
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

/* One (box, subject) answer over the asked-for window. Each key is combined
 * by its own declared merge class: a COUNTER is added, an LWW or OWNER_ONLY
 * key keeps the latest statement in chain order. `state[k]` distinguishes
 * "measured zero" from "no row ever carried this key", which is the whole
 * point of the absent rule. */
struct zcl_fleet_bucket {
    uint8_t box_id[ZCL_FLEET_ID_BYTES];
    uint16_t subject;
    uint64_t rows;
    int64_t last_ts;
    int64_t value[ZCL_FLEET_PAIR_KEY_MAX + 1];
    uint8_t state[ZCL_FLEET_PAIR_KEY_MAX + 1]; /* enum zcl_fleet_field_state */
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

/* One (task_class, model) answer over the experiment events the index
 * kept. Medians and the predicted-vs-actual ratio need per-row values,
 * so this walk is over those events rather than over merged day cells.
 * Rates and ratios are basis points, never a float. */
struct zcl_fleet_experiment_group {
    uint8_t task_class;
    uint8_t model;
    uint64_t predicts;
    uint64_t results;
    uint64_t lands;
    uint64_t unpredicted;
    int64_t median_wall_s;
    int64_t median_tokens;
    int64_t pred_actual_bp;
    uint8_t have_median_wall;
    uint8_t have_median_tokens;
    uint8_t have_pred_actual;
};

enum zcl_fleet_status zcl_fleet_ledger_experiment_stats(
    const struct zcl_fleet_ledger *ledger,
    struct zcl_fleet_experiment_group *out, size_t cap, size_t *count,
    uint64_t *unpredicted, uint64_t *index_us);

uint64_t zcl_fleet_ledger_experiment_overflow(const struct zcl_fleet_ledger *l);

/* The UTC day number a timestamp falls in — the index's bucket key, exposed
 * because a caller rendering a table needs the same arithmetic. */
uint32_t zcl_fleet_day_of(int64_t ts_unix);

#endif /* ZCL_FLEET_LEDGER_H */
