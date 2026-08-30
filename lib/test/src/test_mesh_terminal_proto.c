/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Adversarial acceptance for the mesh terminal wire codec and
 * receipt proof (open/receipt/data/resize/close), mirroring
 * test_mesh_status_proto. Every refusal below must arrive by NAME, never
 * as a generic failure, so a decode/validate regression cannot pass by
 * refusing for the wrong reason. */

#include "test/test_core.h"

#include "crypto/ed25519.h"
#include "models/mesh_pairing.h"
#include "session/mesh_terminal_proto.h"

#include <string.h>

static_assert(MESH_TERMINAL_CAP_TERMINAL_EXEC == MESH_PAIRING_CAP_TERMINAL_EXEC,
              "terminal wire capability must match the pairing authority bit");

static void fill_bytes(uint8_t out[32], uint8_t first)
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(first + i);
}

static bool bytes_are_zero(const void *bytes, size_t count)
{
    const uint8_t *p = bytes;
    uint8_t any = 0;
    for (size_t i = 0; i < count; i++)
        any |= p[i];
    return any == 0;
}

static void make_open(struct mesh_terminal_open_v1 *open)
{
    memset(open, 0, sizeof(*open));
    open->version = MESH_TERMINAL_PROTO_VERSION;
    open->flags = MESH_TERMINAL_PROTO_FLAGS_NONE;
    open->capability = MESH_TERMINAL_CAP_TERMINAL_EXEC;
    fill_bytes(open->terminal_id, 0x11);
    fill_bytes(open->pairing_id, 0xa1);
    fill_bytes(open->network_genesis, 0x21);
    fill_bytes(open->target_master_pubkey, 0x31);
    fill_bytes(open->requester_master_pubkey, 0x41);
    fill_bytes(open->requester_noise_static, 0x51);
    fill_bytes(open->transcript_hash, 0x61);
    open->connection_generation = UINT64_C(0x1020304050607080);
    open->issued_unix = UINT64_C(1800000000);
    open->expires_unix =
        open->issued_unix + MESH_TERMINAL_OPEN_MAX_LIFETIME_SECONDS;
    open->cols = 80;
    open->rows = 24;
}

/* Build and sign an exact receipt answering `open`; returns false when the
 * (status, capsule) combination itself is malformed — the caller asserts
 * that outcome for the capsule-discipline cases. */
static bool make_receipt(struct mesh_terminal_receipt_v1 *receipt,
                         const struct mesh_terminal_open_v1 *open,
                         enum mesh_terminal_receipt_status status,
                         const uint8_t *capsule, size_t capsule_len,
                         const uint8_t seed[32])
{
    uint8_t secret[32];

    if (capsule_len > MESH_TERMINAL_CAPSULE_MAX)
        return false;
    memset(receipt, 0, sizeof(*receipt));
    receipt->version = MESH_TERMINAL_PROTO_VERSION;
    receipt->flags = MESH_TERMINAL_PROTO_FLAGS_NONE;
    receipt->status = status;
    memcpy(receipt->request_id, open->terminal_id, 32);
    if (mesh_terminal_open_v1_root(open, receipt->request_root) !=
        MESH_TERMINAL_PROTO_OK)
        return false;
    memcpy(receipt->network_genesis, open->network_genesis, 32);
    memcpy(receipt->pairing_id, open->pairing_id, 32);
    memcpy(receipt->responder_master_pubkey,
           open->target_master_pubkey, 32);
    ed25519_keypair(receipt->responder_online_pubkey, secret, seed);
    memset(secret, 0, sizeof(secret));
    fill_bytes(receipt->responder_noise_static, 0x42);
    memcpy(receipt->transcript_hash, open->transcript_hash, 32);
    receipt->connection_generation = open->connection_generation;
    receipt->revocation_generation = 7;
    receipt->observed_unix = open->issued_unix + 1;
    receipt->expires_unix = open->expires_unix;
    receipt->capsule_len = (uint16_t)capsule_len;
    if (capsule_len != 0)
        memcpy(receipt->capsule, capsule, capsule_len);
    if (mesh_terminal_capsule_v1_root(receipt->capsule, receipt->capsule_len,
                                      receipt->capsule_root) !=
        MESH_TERMINAL_PROTO_OK)
        return false;
    return mesh_terminal_receipt_v1_sign(receipt, seed) ==
           MESH_TERMINAL_PROTO_OK;
}

/* ── Open ────────────────────────────────────────────────────────────── */

static int open_roundtrip_and_root(void)
{
    int failures = 0;
    TEST_CASE("terminal open: roundtrip, magic, deterministic root") {
        struct mesh_terminal_open_v1 open, decoded;
        uint8_t wire[MESH_TERMINAL_OPEN_V1_WIRE_BYTES];
        uint8_t root[32], root_again[32], root_other[32];

        make_open(&open);
        ASSERT_EQ(mesh_terminal_open_v1_encode(&open, wire),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(memcmp(wire, "ZMTO1", 5) == 0);
        ASSERT_EQ(mesh_terminal_open_v1_decode(&decoded, wire, sizeof(wire)),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(memcmp(&open, &decoded, sizeof(open)) == 0);
        ASSERT_EQ(mesh_terminal_open_v1_root(&open, root),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT_EQ(mesh_terminal_open_v1_root(&decoded, root_again),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(memcmp(root, root_again, 32) == 0);

        /* Any single flipped wire byte yields a different bound root —
         * the transcript identity the receipt answers is byte-exact. */
        wire[40] ^= 0x40;
        ASSERT_EQ(mesh_terminal_open_v1_decode(&decoded, wire, sizeof(wire)),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT_EQ(mesh_terminal_open_v1_root(&decoded, root_other),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(memcmp(root, root_other, 32) != 0);
    } TEST_END
    return failures;
}

static int open_strict_shape(void)
{
    int failures = 0;
    TEST_CASE("terminal open: every malformed shape and wire refused by name") {
        struct mesh_terminal_open_v1 open, trial, decoded;
        uint8_t wire[MESH_TERMINAL_OPEN_V1_WIRE_BYTES];
        uint8_t short_wire[MESH_TERMINAL_OPEN_V1_WIRE_BYTES - 1];
        uint8_t long_wire[MESH_TERMINAL_OPEN_V1_WIRE_BYTES + 1];

        make_open(&open);

        trial = open; trial.version = 0;
        ASSERT_EQ(mesh_terminal_open_v1_validate(&trial),
                  MESH_TERMINAL_PROTO_VERSION_INVALID);
        trial = open; trial.version = 2;
        ASSERT_EQ(mesh_terminal_open_v1_validate(&trial),
                  MESH_TERMINAL_PROTO_VERSION_INVALID);
        trial = open; trial.flags = 1;
        ASSERT_EQ(mesh_terminal_open_v1_validate(&trial),
                  MESH_TERMINAL_PROTO_FLAGS);
        /* Only the exact terminal-exec capability opens a terminal —
         * status-read alone and any superset are both refused. */
        trial = open; trial.capability = MESH_PAIRING_CAP_STATUS_READ;
        ASSERT_EQ(mesh_terminal_open_v1_validate(&trial),
                  MESH_TERMINAL_PROTO_CAPABILITY);
        trial = open;
        trial.capability = MESH_PAIRING_CAP_STATUS_READ |
                           MESH_PAIRING_CAP_TERMINAL_EXEC;
        ASSERT_EQ(mesh_terminal_open_v1_validate(&trial),
                  MESH_TERMINAL_PROTO_CAPABILITY);

        /* Each identity field is critical: zeroing any one is refused. */
        uint8_t *critical[] = {
            trial.terminal_id, trial.pairing_id, trial.network_genesis,
            trial.target_master_pubkey, trial.requester_master_pubkey,
            trial.requester_noise_static, trial.transcript_hash,
        };
        for (size_t i = 0; i < sizeof(critical) / sizeof(critical[0]); i++) {
            trial = open;
            memset(critical[i], 0, 32);
            ASSERT_EQ(mesh_terminal_open_v1_validate(&trial),
                      MESH_TERMINAL_PROTO_FIELD);
        }
        trial = open; trial.connection_generation = 0;
        ASSERT_EQ(mesh_terminal_open_v1_validate(&trial),
                  MESH_TERMINAL_PROTO_FIELD);

        trial = open; trial.cols = 0;
        ASSERT_EQ(mesh_terminal_open_v1_validate(&trial),
                  MESH_TERMINAL_PROTO_GEOMETRY);
        trial = open; trial.rows = 0;
        ASSERT_EQ(mesh_terminal_open_v1_validate(&trial),
                  MESH_TERMINAL_PROTO_GEOMETRY);
        trial = open; trial.cols = MESH_TERMINAL_MAX_COLS + 1;
        ASSERT_EQ(mesh_terminal_open_v1_validate(&trial),
                  MESH_TERMINAL_PROTO_GEOMETRY);
        trial = open; trial.rows = MESH_TERMINAL_MAX_ROWS + 1;
        ASSERT_EQ(mesh_terminal_open_v1_validate(&trial),
                  MESH_TERMINAL_PROTO_GEOMETRY);

        trial = open; trial.issued_unix = 0;
        ASSERT_EQ(mesh_terminal_open_v1_validate(&trial),
                  MESH_TERMINAL_PROTO_TIME);
        trial = open; trial.expires_unix = trial.issued_unix;
        ASSERT_EQ(mesh_terminal_open_v1_validate(&trial),
                  MESH_TERMINAL_PROTO_TIME);
        trial = open;
        trial.expires_unix = trial.issued_unix +
                             MESH_TERMINAL_OPEN_MAX_LIFETIME_SECONDS + 1;
        ASSERT_EQ(mesh_terminal_open_v1_validate(&trial),
                  MESH_TERMINAL_PROTO_TIME);
        /* The max exactly-60-second window stays valid. */
        trial = open;
        trial.expires_unix = trial.issued_unix +
                             MESH_TERMINAL_OPEN_MAX_LIFETIME_SECONDS;
        ASSERT_EQ(mesh_terminal_open_v1_validate(&trial),
                  MESH_TERMINAL_PROTO_OK);

        /* Wire-level: short, long, and wrong-magic frames are refused and
         * the output struct is always left zeroed. */
        ASSERT_EQ(mesh_terminal_open_v1_encode(&open, wire),
                  MESH_TERMINAL_PROTO_OK);
        memset(&decoded, 0xaa, sizeof(decoded));
        ASSERT_EQ(mesh_terminal_open_v1_decode(&decoded, wire,
                                               sizeof(wire) - 1),
                  MESH_TERMINAL_PROTO_SIZE);
        ASSERT(bytes_are_zero(&decoded, sizeof(decoded)));
        ASSERT_EQ(mesh_terminal_open_v1_decode(&decoded, short_wire,
                                               sizeof(short_wire)),
                  MESH_TERMINAL_PROTO_SIZE);
        ASSERT_EQ(mesh_terminal_open_v1_decode(&decoded, long_wire,
                                               sizeof(long_wire)),
                  MESH_TERMINAL_PROTO_SIZE);
        wire[0] = 'X';
        ASSERT_EQ(mesh_terminal_open_v1_decode(&decoded, wire, sizeof(wire)),
                  MESH_TERMINAL_PROTO_MAGIC);
        ASSERT(bytes_are_zero(&decoded, sizeof(decoded)));
        ASSERT_EQ(mesh_terminal_open_v1_decode(NULL, wire, sizeof(wire)),
                  MESH_TERMINAL_PROTO_NULL);
        ASSERT_EQ(mesh_terminal_open_v1_decode(&decoded, NULL, sizeof(wire)),
                  MESH_TERMINAL_PROTO_NULL);
    } TEST_END
    return failures;
}

/* ── Receipt ─────────────────────────────────────────────────────────── */

static int receipt_ok_roundtrip(void)
{
    int failures = 0;
    TEST_CASE("terminal receipt: OK roundtrip, exact wire size, stable root") {
        static const uint8_t capsule[] = "{\"max_lifetime_s\":60,\"bytes\":"
                                         "262144,\"cols\":80,\"rows\":24}";
        struct mesh_terminal_open_v1 open;
        struct mesh_terminal_receipt_v1 receipt, decoded;
        static const uint8_t seed[32] = {1};
        uint8_t wire[MESH_TERMINAL_RECEIPT_V1_MAX_WIRE_BYTES];
        size_t wire_len = 0;
        uint8_t root[32], root_again[32];

        make_open(&open);
        ASSERT(make_receipt(&receipt, &open, MESH_TERMINAL_RECEIPT_OK,
                            capsule, sizeof(capsule) - 1, seed));
        ASSERT_EQ(mesh_terminal_receipt_v1_encode(
                      &receipt, wire, sizeof(wire), &wire_len),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(wire_len == MESH_TERMINAL_RECEIPT_V1_FIXED_BYTES +
                               sizeof(capsule) - 1);
        ASSERT_EQ(mesh_terminal_receipt_v1_wire_size(&receipt), wire_len);
        ASSERT(memcmp(wire, "ZMTK1", 5) == 0);
        ASSERT_EQ(mesh_terminal_receipt_v1_decode(&decoded, wire, wire_len),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(memcmp(&receipt, &decoded, sizeof(receipt)) == 0);
        ASSERT_EQ(mesh_terminal_receipt_v1_root(&receipt, root),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT_EQ(mesh_terminal_receipt_v1_root(&decoded, root_again),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(memcmp(root, root_again, 32) == 0);
    } TEST_END
    return failures;
}

static int receipt_tampering_refused(void)
{
    int failures = 0;
    TEST_CASE("terminal receipt: tampering is refused by name") {
        static const uint8_t capsule[] = "evidence";
        struct mesh_terminal_open_v1 open;
        struct mesh_terminal_receipt_v1 receipt, wrong_key;
        static const uint8_t seed[32] = {2};
        static const uint8_t other_seed[32] = {3};
        size_t wire_len = 0;
        uint8_t wire[MESH_TERMINAL_RECEIPT_V1_MAX_WIRE_BYTES];

        make_open(&open);
        ASSERT(make_receipt(&receipt, &open, MESH_TERMINAL_RECEIPT_OK,
                            capsule, sizeof(capsule) - 1, seed));

        /* A flipped evidence byte breaks the capsule root the signature
         * covers — refused as CAPSULE_ROOT, not as a generic failure. */
        receipt.capsule[0] ^= 1;
        ASSERT_EQ(mesh_terminal_receipt_v1_validate(&receipt),
                  MESH_TERMINAL_PROTO_CAPSULE_ROOT);
        receipt.capsule[0] ^= 1;

        receipt.signature[0] ^= 1;
        ASSERT_EQ(mesh_terminal_receipt_v1_validate(&receipt),
                  MESH_TERMINAL_PROTO_SIGNATURE);
        receipt.signature[0] ^= 1;

        /* The seed must be the one behind responder_online_pubkey. */
        wrong_key = receipt;
        ASSERT_EQ(mesh_terminal_receipt_v1_sign(&wrong_key, other_seed),
                  MESH_TERMINAL_PROTO_KEY_MISMATCH);

        /* An oversized capsule is refused before any hashing — into a
         * scratch root, since every root call writes its out-param even
         * when it refuses. */
        uint8_t scratch_root[32];
        ASSERT_EQ(mesh_terminal_capsule_v1_root(
                      receipt.capsule, MESH_TERMINAL_CAPSULE_MAX + 1,
                      scratch_root),
                  MESH_TERMINAL_PROTO_SIZE);
        ASSERT(bytes_are_zero(scratch_root, sizeof(scratch_root)));
        /* A short buffer cannot hold the encoded receipt. */
        ASSERT_EQ(mesh_terminal_receipt_v1_encode(
                      &receipt, wire, MESH_TERMINAL_RECEIPT_V1_FIXED_BYTES - 1,
                      &wire_len),
                  MESH_TERMINAL_PROTO_SIZE);
        ASSERT_EQ(wire_len, 0);
        ASSERT_EQ(mesh_terminal_receipt_v1_encode(NULL, wire, sizeof(wire),
                                                  &wire_len),
                  MESH_TERMINAL_PROTO_NULL);
    } TEST_END
    return failures;
}

static int receipt_capsule_discipline(void)
{
    int failures = 0;
    TEST_CASE("terminal receipt: capsule discipline per status") {
        static const uint8_t capsule[] = "{\"bytes_in\":4,\"bytes_out\":9}";
        struct mesh_terminal_open_v1 open;
        struct mesh_terminal_receipt_v1 receipt;
        static const uint8_t seed[32] = {4};

        make_open(&open);
        /* OK and CLOSED are the only capsule-carrying verdicts. */
        ASSERT(make_receipt(&receipt, &open, MESH_TERMINAL_RECEIPT_OK,
                            capsule, sizeof(capsule) - 1, seed));
        ASSERT_EQ(mesh_terminal_receipt_v1_validate(&receipt),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(make_receipt(&receipt, &open, MESH_TERMINAL_RECEIPT_CLOSED,
                            capsule, sizeof(capsule) - 1, seed));
        ASSERT_EQ(mesh_terminal_receipt_v1_validate(&receipt),
                  MESH_TERMINAL_PROTO_OK);
        /* An OK receipt without its session-evidence capsule is malformed. */
        ASSERT(!make_receipt(&receipt, &open, MESH_TERMINAL_RECEIPT_OK,
                             NULL, 0, seed));
        /* Every named refusal is bare: a capsule-bearing refusal is refused
         * as STATUS, and the bare refusal validates. */
        ASSERT(!make_receipt(&receipt, &open,
                             MESH_TERMINAL_RECEIPT_NOT_PAIRED,
                             capsule, sizeof(capsule) - 1, seed));
        ASSERT(make_receipt(&receipt, &open,
                            MESH_TERMINAL_RECEIPT_NOT_PAIRED,
                            NULL, 0, seed));
        ASSERT_EQ(mesh_terminal_receipt_v1_validate(&receipt),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(make_receipt(&receipt, &open,
                            MESH_TERMINAL_RECEIPT_CONFINEMENT_UNAVAILABLE,
                            NULL, 0, seed));
        ASSERT_EQ(mesh_terminal_receipt_v1_validate(&receipt),
                  MESH_TERMINAL_PROTO_OK);
        /* An out-of-range status never validates. */
        receipt.status = (enum mesh_terminal_receipt_status)(
            MESH_TERMINAL_RECEIPT_INTERNAL + 1);
        ASSERT_EQ(mesh_terminal_receipt_v1_validate(&receipt),
                  MESH_TERMINAL_PROTO_STATUS);
    } TEST_END
    return failures;
}

static int receipt_decode_refusals(void)
{
    int failures = 0;
    TEST_CASE("terminal receipt: decode refuses truncated/oversized/magic") {
        static const uint8_t capsule[] = "evidence";
        struct mesh_terminal_open_v1 open;
        struct mesh_terminal_receipt_v1 receipt, decoded;
        static const uint8_t seed[32] = {5};
        uint8_t wire[MESH_TERMINAL_RECEIPT_V1_MAX_WIRE_BYTES];
        size_t wire_len = 0;

        make_open(&open);
        ASSERT(make_receipt(&receipt, &open, MESH_TERMINAL_RECEIPT_OK,
                            capsule, sizeof(capsule) - 1, seed));
        ASSERT_EQ(mesh_terminal_receipt_v1_encode(
                      &receipt, wire, sizeof(wire), &wire_len),
                  MESH_TERMINAL_PROTO_OK);
        memset(&decoded, 0, sizeof(decoded));
        ASSERT_EQ(mesh_terminal_receipt_v1_decode(&decoded, wire,
                                                  wire_len - 1),
                  MESH_TERMINAL_PROTO_SIZE);
        ASSERT(bytes_are_zero(&decoded, sizeof(decoded)));
        wire[0] = 'X';
        ASSERT_EQ(mesh_terminal_receipt_v1_decode(&decoded, wire, wire_len),
                  MESH_TERMINAL_PROTO_MAGIC);
        ASSERT(bytes_are_zero(&decoded, sizeof(decoded)));
        /* A capsule_len the wire length disagrees with is a size refusal.
         * capsule_len lives at unsigned-offset 14: magic 8 + version 2 +
         * flags 2 + status 2. */
        ASSERT(make_receipt(&receipt, &open, MESH_TERMINAL_RECEIPT_OK,
                            capsule, sizeof(capsule) - 1, seed));
        ASSERT_EQ(mesh_terminal_receipt_v1_encode(
                      &receipt, wire, sizeof(wire), &wire_len),
                  MESH_TERMINAL_PROTO_OK);
        wire[14] = 4; /* capsule_len low byte: claims 4 more than carried */
        ASSERT_EQ(mesh_terminal_receipt_v1_decode(&decoded, wire, wire_len),
                  MESH_TERMINAL_PROTO_SIZE);
        ASSERT(bytes_are_zero(&decoded, sizeof(decoded)));
    } TEST_END
    return failures;
}

static int receipt_matches_open(void)
{
    int failures = 0;
    TEST_CASE("terminal receipt: binds exactly the open it answers") {
        struct mesh_terminal_open_v1 open, trial_open;
        struct mesh_terminal_receipt_v1 receipt;
        static const uint8_t seed[32] = {6};

        make_open(&open);
        ASSERT(make_receipt(&receipt, &open, MESH_TERMINAL_RECEIPT_OK,
                            (const uint8_t *)"ok", 2, seed));
        ASSERT_EQ(mesh_terminal_receipt_v1_matches_open(&receipt, &open),
                  MESH_TERMINAL_PROTO_OK);

        /* Tampering the receipt breaks its signature before any binding
         * comparison can run — the tamper is refused as SIGNATURE. */
        receipt.request_id[0] ^= 1;
        ASSERT_EQ(mesh_terminal_receipt_v1_matches_open(&receipt, &open),
                  MESH_TERMINAL_PROTO_SIGNATURE);
        receipt.request_id[0] ^= 1;

        /* Tampering the OPEN leaves the receipt's signature valid but
         * breaks every bound binding — each is FIELD, by name. */
        uint8_t *bound_open[] = {
            open.terminal_id, open.pairing_id, open.network_genesis,
            open.target_master_pubkey, open.transcript_hash,
        };
        for (size_t i = 0;
             i < sizeof(bound_open) / sizeof(bound_open[0]); i++) {
            bound_open[i][0] ^= 1;
            ASSERT_EQ(mesh_terminal_receipt_v1_matches_open(&receipt, &open),
                      MESH_TERMINAL_PROTO_FIELD);
            bound_open[i][0] ^= 1;
        }
        trial_open = open;
        trial_open.connection_generation++;
        ASSERT_EQ(mesh_terminal_receipt_v1_matches_open(&receipt, &trial_open),
                  MESH_TERMINAL_PROTO_FIELD);

        /* TIME is only reachable with an honestly-signed receipt: the
         * open is root-bound (any change to it is FIELD, above), so a
         * mistimed answer must come from the responder's own signing. A
         * receipt that predates the open, lands after the window shut,
         * or outlives the window is each refused by name. */
        struct mesh_terminal_receipt_v1 mistimed;
        ASSERT(make_receipt(&mistimed, &open, MESH_TERMINAL_RECEIPT_OK,
                            (const uint8_t *)"ok", 2, seed));
        mistimed.observed_unix = open.issued_unix - 1;
        mistimed.expires_unix = mistimed.observed_unix + 60;
        ASSERT_EQ(mesh_terminal_receipt_v1_sign(&mistimed, seed),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT_EQ(mesh_terminal_receipt_v1_matches_open(&mistimed, &open),
                  MESH_TERMINAL_PROTO_TIME);

        ASSERT(make_receipt(&mistimed, &open, MESH_TERMINAL_RECEIPT_OK,
                            (const uint8_t *)"ok", 2, seed));
        mistimed.observed_unix = open.expires_unix + 1;
        mistimed.expires_unix = mistimed.observed_unix + 60;
        ASSERT_EQ(mesh_terminal_receipt_v1_sign(&mistimed, seed),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT_EQ(mesh_terminal_receipt_v1_matches_open(&mistimed, &open),
                  MESH_TERMINAL_PROTO_TIME);

        ASSERT(make_receipt(&mistimed, &open, MESH_TERMINAL_RECEIPT_OK,
                            (const uint8_t *)"ok", 2, seed));
        mistimed.expires_unix = open.expires_unix + 1;
        ASSERT_EQ(mesh_terminal_receipt_v1_sign(&mistimed, seed),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT_EQ(mesh_terminal_receipt_v1_matches_open(&mistimed, &open),
                  MESH_TERMINAL_PROTO_TIME);
    } TEST_END
    return failures;
}

static int receipt_closed_after_window(void)
{
    int failures = 0;
    TEST_CASE("terminal receipt: CLOSED may land after the open window shut") {
        struct mesh_terminal_open_v1 open;
        struct mesh_terminal_receipt_v1 receipt;
        static const uint8_t capsule[] = "{\"duration_s\":3600}";
        static const uint8_t seed[32] = {7};

        make_open(&open);
        /* A session that ran an hour closes long after the 60-second answer
         * window; the CLOSED receipt only has to postdate the open's
         * issue. The receipt's own lifetime anchor moves with its fresh
         * observation (expires must sit within 60 s of observed for the
         * receipt shape to validate at all). */
        ASSERT(make_receipt(&receipt, &open, MESH_TERMINAL_RECEIPT_CLOSED,
                            capsule, sizeof(capsule) - 1, seed));
        receipt.observed_unix = open.issued_unix + 3600;
        receipt.expires_unix = receipt.observed_unix + 60;
        ASSERT_EQ(mesh_terminal_receipt_v1_sign(&receipt, seed),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT_EQ(mesh_terminal_receipt_v1_matches_open(&receipt, &open),
                  MESH_TERMINAL_PROTO_OK);
        /* ...but it still cannot predate the open. */
        receipt.observed_unix = open.issued_unix - 1;
        receipt.expires_unix = receipt.observed_unix + 60;
        ASSERT_EQ(mesh_terminal_receipt_v1_sign(&receipt, seed),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT_EQ(mesh_terminal_receipt_v1_matches_open(&receipt, &open),
                  MESH_TERMINAL_PROTO_TIME);
    } TEST_END
    return failures;
}

/* ── Data / resize / close frames ────────────────────────────────────── */

static int data_frame_roundtrip(void)
{
    int failures = 0;
    TEST_CASE("terminal data: roundtrip, max payload, bounds, exact size") {
        struct mesh_terminal_data_v1 data, decoded;
        uint8_t wire[MESH_TERMINAL_DATA_V1_MAX_WIRE_BYTES];
        size_t wire_len = 0;

        memset(&data, 0, sizeof(data));
        fill_bytes(data.terminal_id, 0x77);
        data.seq = UINT64_C(0xdeadbeefcafe0001);
        data.payload_len = 11;
        memcpy(data.payload, "ls -la\r\n", 8);
        ASSERT_EQ(mesh_terminal_data_v1_encode(&data, wire, sizeof(wire),
                                               &wire_len),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(wire_len == MESH_TERMINAL_DATA_V1_HEADER_BYTES + 11);
        ASSERT(memcmp(wire, "ZMTD1", 5) == 0);
        ASSERT_EQ(mesh_terminal_data_v1_decode(&decoded, wire, wire_len),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(memcmp(&data, &decoded, sizeof(data)) == 0);

        /* The full 3072-byte payload is legal; one byte more is not. */
        data.payload_len = MESH_TERMINAL_DATA_PAYLOAD_MAX;
        ASSERT_EQ(mesh_terminal_data_v1_encode(&data, wire, sizeof(wire),
                                               &wire_len),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(wire_len == MESH_TERMINAL_DATA_V1_MAX_WIRE_BYTES);
        data.payload_len = MESH_TERMINAL_DATA_PAYLOAD_MAX + 1;
        ASSERT_EQ(mesh_terminal_data_v1_encode(&data, wire, sizeof(wire),
                                               &wire_len),
                  MESH_TERMINAL_PROTO_SIZE);
        ASSERT_EQ(wire_len, 0);

        /* A terminal_id of all zeroes is not a frame. */
        memset(data.terminal_id, 0, 32);
        data.payload_len = 4;
        ASSERT_EQ(mesh_terminal_data_v1_encode(&data, wire, sizeof(wire),
                                               &wire_len),
                  MESH_TERMINAL_PROTO_FIELD);
    } TEST_END
    return failures;
}

static int data_frame_decode_refusals(void)
{
    int failures = 0;
    TEST_CASE("terminal data: decode refuses truncated/oversized/magic") {
        struct mesh_terminal_data_v1 data, decoded;
        uint8_t wire[MESH_TERMINAL_DATA_V1_MAX_WIRE_BYTES];
        size_t wire_len = 0;

        memset(&data, 0, sizeof(data));
        fill_bytes(data.terminal_id, 0x77);
        data.payload_len = 5;
        memcpy(data.payload, "echo ", 5);
        ASSERT_EQ(mesh_terminal_data_v1_encode(&data, wire, sizeof(wire),
                                               &wire_len),
                  MESH_TERMINAL_PROTO_OK);
        memset(&decoded, 0, sizeof(decoded));
        ASSERT_EQ(mesh_terminal_data_v1_decode(&decoded, wire, wire_len - 1),
                  MESH_TERMINAL_PROTO_SIZE);
        ASSERT(bytes_are_zero(&decoded, sizeof(decoded)));
        ASSERT_EQ(mesh_terminal_data_v1_decode(
                      &decoded, wire,
                      MESH_TERMINAL_DATA_V1_HEADER_BYTES +
                          MESH_TERMINAL_DATA_PAYLOAD_MAX + 1),
                  MESH_TERMINAL_PROTO_SIZE);
        wire[0] = 'X';
        ASSERT_EQ(mesh_terminal_data_v1_decode(&decoded, wire, wire_len),
                  MESH_TERMINAL_PROTO_MAGIC);
        ASSERT(bytes_are_zero(&decoded, sizeof(decoded)));
        /* A header payload_len the wire length disagrees with is refused.
         * payload_len lives at offset 48: magic 8 + terminal_id 32 +
         * seq 8. */
        ASSERT_EQ(mesh_terminal_data_v1_encode(&data, wire, sizeof(wire),
                                               &wire_len),
                  MESH_TERMINAL_PROTO_OK);
        wire[48] = 9; /* payload_len low byte: claims 9, wire carries 5 */
        ASSERT_EQ(mesh_terminal_data_v1_decode(&decoded, wire, wire_len),
                  MESH_TERMINAL_PROTO_SIZE);
        ASSERT(bytes_are_zero(&decoded, sizeof(decoded)));
    } TEST_END
    return failures;
}

static int resize_roundtrip_and_bounds(void)
{
    int failures = 0;
    TEST_CASE("terminal resize: roundtrip and geometry bounds") {
        struct mesh_terminal_resize_v1 resize, decoded;
        uint8_t wire[MESH_TERMINAL_RESIZE_V1_WIRE_BYTES];

        memset(&resize, 0, sizeof(resize));
        fill_bytes(resize.terminal_id, 0x88);
        resize.cols = 80;
        resize.rows = 24;
        ASSERT_EQ(mesh_terminal_resize_v1_encode(&resize, wire),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(memcmp(wire, "ZMTW1", 5) == 0);
        ASSERT_EQ(mesh_terminal_resize_v1_decode(&decoded, wire, sizeof(wire)),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(memcmp(&resize, &decoded, sizeof(resize)) == 0);

        resize.cols = MESH_TERMINAL_MAX_COLS;
        resize.rows = MESH_TERMINAL_MAX_ROWS;
        ASSERT_EQ(mesh_terminal_resize_v1_encode(&resize, wire),
                  MESH_TERMINAL_PROTO_OK);
        resize.cols = (uint16_t)(MESH_TERMINAL_MAX_COLS + 1);
        ASSERT_EQ(mesh_terminal_resize_v1_encode(&resize, wire),
                  MESH_TERMINAL_PROTO_GEOMETRY);
        resize.cols = 80;
        resize.rows = 0;
        ASSERT_EQ(mesh_terminal_resize_v1_encode(&resize, wire),
                  MESH_TERMINAL_PROTO_GEOMETRY);
        memset(resize.terminal_id, 0, 32);
        resize.rows = 24;
        ASSERT_EQ(mesh_terminal_resize_v1_encode(&resize, wire),
                  MESH_TERMINAL_PROTO_FIELD);

        fill_bytes(resize.terminal_id, 0x88);
        resize.rows = 0;
        ASSERT_EQ(mesh_terminal_resize_v1_encode(&resize, wire),
                  MESH_TERMINAL_PROTO_GEOMETRY);
        resize.rows = 24;
        ASSERT_EQ(mesh_terminal_resize_v1_encode(&resize, wire),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT_EQ(mesh_terminal_resize_v1_decode(&decoded, wire,
                                                 sizeof(wire) - 1),
                  MESH_TERMINAL_PROTO_SIZE);
        wire[0] = 'X';
        ASSERT_EQ(mesh_terminal_resize_v1_decode(&decoded, wire, sizeof(wire)),
                  MESH_TERMINAL_PROTO_MAGIC);
        ASSERT(bytes_are_zero(&decoded, sizeof(decoded)));
    } TEST_END
    return failures;
}

static int close_roundtrip_and_bounds(void)
{
    int failures = 0;
    TEST_CASE("terminal close: roundtrip and reason bound") {
        struct mesh_terminal_close_v1 close_frame, decoded;
        uint8_t wire[MESH_TERMINAL_CLOSE_V1_WIRE_BYTES];

        memset(&close_frame, 0, sizeof(close_frame));
        fill_bytes(close_frame.terminal_id, 0x99);
        close_frame.reason = MESH_TERMINAL_CLOSE_REQUESTED;
        ASSERT_EQ(mesh_terminal_close_v1_encode(&close_frame, wire),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(sizeof(wire) == MESH_TERMINAL_CLOSE_V1_WIRE_BYTES &&
               memcmp(wire, "ZMTC1", 5) == 0);
        ASSERT_EQ(mesh_terminal_close_v1_decode(&decoded, wire, sizeof(wire)),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT(memcmp(&close_frame, &decoded, sizeof(close_frame)) == 0);

        close_frame.reason = MESH_TERMINAL_CLOSE_SHUTDOWN;
        ASSERT_EQ(mesh_terminal_close_v1_encode(&close_frame, wire),
                  MESH_TERMINAL_PROTO_OK);
        close_frame.reason = (uint8_t)(MESH_TERMINAL_CLOSE_SHUTDOWN + 1);
        ASSERT_EQ(mesh_terminal_close_v1_encode(&close_frame, wire),
                  MESH_TERMINAL_PROTO_REASON);
        memset(close_frame.terminal_id, 0, 32);
        close_frame.reason = MESH_TERMINAL_CLOSE_REQUESTED;
        ASSERT_EQ(mesh_terminal_close_v1_encode(&close_frame, wire),
                  MESH_TERMINAL_PROTO_FIELD);

        fill_bytes(close_frame.terminal_id, 0x99);
        ASSERT_EQ(mesh_terminal_close_v1_encode(&close_frame, wire),
                  MESH_TERMINAL_PROTO_OK);
        ASSERT_EQ(mesh_terminal_close_v1_decode(&decoded, wire,
                                                sizeof(wire) - 1),
                  MESH_TERMINAL_PROTO_SIZE);
        /* An out-of-range reason byte on the wire is refused on decode. */
        wire[sizeof(wire) - 1] = 200;
        ASSERT_EQ(mesh_terminal_close_v1_decode(&decoded, wire, sizeof(wire)),
                  MESH_TERMINAL_PROTO_FIELD);
        ASSERT(bytes_are_zero(&decoded, sizeof(decoded)));
        wire[0] = 'X';
        wire[sizeof(wire) - 1] = MESH_TERMINAL_CLOSE_REQUESTED;
        ASSERT_EQ(mesh_terminal_close_v1_decode(&decoded, wire, sizeof(wire)),
                  MESH_TERMINAL_PROTO_MAGIC);
    } TEST_END
    return failures;
}

int test_mesh_terminal_proto(void)
{
    int failures = 0;
    printf("\n=== Mesh Terminal Proto Tests ===\n");
    failures += open_roundtrip_and_root();
    failures += open_strict_shape();
    failures += receipt_ok_roundtrip();
    failures += receipt_tampering_refused();
    failures += receipt_capsule_discipline();
    failures += receipt_decode_refusals();
    failures += receipt_matches_open();
    failures += receipt_closed_after_window();
    failures += data_frame_roundtrip();
    failures += data_frame_decode_refusals();
    failures += resize_roundtrip_and_bounds();
    failures += close_roundtrip_and_bounds();
    printf("Mesh terminal proto: %d failures\n", failures);
    return failures;
}
