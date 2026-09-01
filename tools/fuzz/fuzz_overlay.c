/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * fuzz_overlay — libFuzzer harness for every overlay wire decoder that
 * reads attacker-chosen bytes: the five OP_RETURN parsers (ZSLP, ZNAM,
 * ZANC, ZID anchor, ZDIR) and the four zid record codecs (identity doc,
 * release body, inclusion proof, signed endpoint, service descriptor).
 *
 * THE REACH PATH. Anyone who can get a transaction into a block chooses
 * the bytes of an OP_RETURN output outright — there is no signature, no
 * script execution and no size discipline beyond the relay cap on the
 * payload, and every indexing node parses it:
 *
 *   peer block -> connect_block -> explorer index fold
 *     -> contexts/explorer/models/src/explorer_index_overlays.c — one dispatch table,
 *        keyed on the four lokad bytes, five entries:
 *          slp_parse(tx->vout[0].script_pub_key.data, ...)
 *          znam_parse(script, script_len, ...)
 *          zanc_parse(script, script_len, ...)
 *          zid_anchor_parse(...) via explorer_index_apply_zid_overlay
 *     -> contexts/naming/models/src/explorer_index_zdir.c:161
 *          zdir_parse(script, script_len, ...)
 *   and again on render, contexts/explorer/controllers/src/explorer_controller_block.c:220
 *   and explorer_controller_tx.c:379, for anyone browsing the explorer.
 *
 * The zid codecs take the same shape of input from a different pipe:
 * contexts/commons/modules/vcs/src/zdesc_swarm.c:148 and contexts/commons/modules/vcs/src/zendp_swarm.c:248 call
 * zid_doc_decode on swarm-fetched record bytes BEFORE any signature is
 * checked, then hand the decoded body to zdesc_decode_body /
 * zendp_decode_body. So the decoders below run on unauthenticated bytes
 * in every case; the signature, when there is one, is checked after.
 *
 * None of these nine functions allocates — they are pure codecs writing
 * into caller-owned structs (verified: slp/znam/zanc/zid_anchor/zdir fill
 * fixed-size message structs via read_push/overlay_reader, which return
 * pointers INTO the input; contexts/wallet/modules/zid is documented "no allocation anywhere:
 * caller buffers only"). There is therefore nothing to free on either the
 * success or the failure branch, and no output buffer outlives an input.
 * What must hold is that not one of them reads past `size` or faults on
 * ANY input. Runs with -fsanitize=fuzzer,address,undefined under clang.
 *
 * Byte 0 selects the decoder and the rest is the payload, so one binary
 * reaches all of them and libFuzzer learns the leading discriminator
 * within the first few hundred execs.
 *
 * Set ZCL_FUZZ_OVERLAY_ARM_STATS=1 in the environment to have the run
 * print a per-arm execution count on exit. That is how you check that a
 * newly added arm is actually being reached rather than merely present:
 * an arm nothing ever runs reads as covered while testing nothing.
 */

#include "chain/chainparams.h"
#include "zanc/zanc.h"
#include "zdir/zdir.h"
#include "zid/zdesc.h"
#include "zid/zendp.h"
#include "zid/zid.h"
#include "zid/zid_anchor.h"
#include "znam/znam.h"
#include "zslp/slp.h"

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Required by the dependency graph of the sources linked into this
 * binary (process/sync globals). Provided by main.c in the real binary
 * and by test.c in the suite; the fuzzer is neither, so the global lives
 * here — same as fuzz_block.c and fuzz_tx_bundle.c. */
volatile sig_atomic_t g_shutdown_requested = 0;

/* Number of demux arms. Keep in sync with the switch below. Byte 0 of
 * every seed in tests/harness/fuzz_seeds/overlay/ is the literal arm index, so
 * adding an arm here does not silently re-route the existing corpus. */
#define FUZZ_OVERLAY_ARMS 9

/* Every record here is small: MAX_OP_RETURN_RELAY is 223, ZID_DOC_MAX is
 * 1139 and ZID_PROOF_WIRE_MAX is 2067. Cap well above the largest so the
 * corpus stays in the interesting range, and so the uint16_t body_len
 * casts below are always exact. */
#define FUZZ_OVERLAY_MAX_INPUT 8192u

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* Per-arm execution counts, reported at exit when the run asked for them
 * (ZCL_FUZZ_OVERLAY_ARM_STATS=1). One increment per exec, no locking: a
 * libFuzzer worker is single-threaded, and this is a reachability check,
 * not a measurement anything depends on. */
static unsigned long g_arm_hits[FUZZ_OVERLAY_ARMS];
static bool g_arm_stats;

static const char *const g_arm_names[FUZZ_OVERLAY_ARMS] = {
    "slp_parse", "znam_parse", "zdir_parse", "zid_doc_decode",
    "zendp_decode_body", "zdesc_decode_body", "zid_proof_decode",
    "zanc_parse", "zid_anchor_parse",
};

static void fuzz_overlay_report_arms(void)
{
    if (!g_arm_stats) return;
    for (unsigned i = 0; i < FUZZ_OVERLAY_ARMS; i++)
        fprintf(stderr, "ARM_HITS %u %-18s %lu\n", i, g_arm_names[i],
                g_arm_hits[i]);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    chain_params_select(CHAIN_MAIN);
    const char *v = getenv("ZCL_FUZZ_OVERLAY_ARM_STATS");
    if (v && v[0] == '1' && v[1] == '\0') {
        g_arm_stats = true;
        atexit(fuzz_overlay_report_arms);
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > FUZZ_OVERLAY_MAX_INPUT)
        return 0;  /* libFuzzer convention: return 0 means "keep going" */

    const uint8_t arm = (uint8_t)(data[0] % FUZZ_OVERLAY_ARMS);
    g_arm_hits[arm]++;
    const uint8_t *payload = data + 1;
    const size_t payload_len = size - 1;
    /* Exact by the size cap above. */
    const uint16_t body_len = (uint16_t)payload_len;

    switch (arm) {
    case 0: {
        /* ZSLP OP_RETURN — GENESIS/MINT/SEND/COMMIT field grammar. */
        struct slp_message msg;
        (void)slp_parse(payload, payload_len, &msg);
        break;
    }
    case 1: {
        /* ZNAM OP_RETURN — the name registry's six commands. */
        struct znam_message msg;
        (void)znam_parse(payload, payload_len, &msg);
        break;
    }
    case 2: {
        /* ZDIR OP_RETURN — the on-chain node directory record. */
        struct zdir_message msg;
        (void)zdir_parse(payload, payload_len, &msg);
        break;
    }
    case 3: {
        /* zid identity document. On a well-formed frame, push the
         * decoded body onward through the two body codecs that consume
         * it — a doc body is exactly as attacker-controlled as the frame
         * around it, and the release decoder is the one with a
         * length-prefixed string pair inside. */
        struct zid_doc doc;
        if (zid_doc_decode(&doc, payload, payload_len)) {
            struct zid_release rel;
            (void)zid_release_decode_body(&rel, doc.body, doc.body_len);

            uint64_t index = 0, num_leaves = 0;
            uint32_t proof_len = 0;
            uint8_t siblings[ZID_TREE_MAX_PEAKS][32];
            (void)zid_proof_decode(&index, &num_leaves, siblings, &proof_len,
                                   doc.body, doc.body_len);
        }
        break;
    }
    case 4: {
        /* zid signed endpoint body ("ZIDE"): flags-driven variable
         * layout, exact-length rule, then the full shape re-check. */
        struct zendp ep;
        (void)zendp_decode_body(&ep, payload, body_len);
        break;
    }
    case 5: {
        /* zid service descriptor body ("ZIDD"): intro_count-driven
         * variable layout plus per-hostname v3 onion re-validation. */
        struct zdesc desc;
        (void)zdesc_decode_body(&desc, payload, body_len);
        break;
    }
    case 6: {
        /* zid MMR inclusion proof wire. Reachable through arm 3 only
         * behind a valid doc frame, which costs libFuzzer a 51-byte
         * prefix and an exact length match; give the proof_len-driven
         * sibling read its own direct arm as well. */
        uint64_t index = 0, num_leaves = 0;
        uint32_t proof_len = 0;
        uint8_t siblings[ZID_TREE_MAX_PEAKS][32];
        (void)zid_proof_decode(&index, &num_leaves, siblings, &proof_len,
                               payload, payload_len);
        break;
    }
    case 7: {
        /* ZANC OP_RETURN — the software/package digest anchor. Same
         * dispatch table as ZSLP/ZNAM/ZDIR above: fixed hash-type and
         * digest fields, then a bounded UTF-8 label whose validator walks
         * multi-byte sequences off a length the script chose. */
        struct zanc_message msg;
        (void)zanc_parse(payload, payload_len, &msg);
        break;
    }
    case 8: {
        /* ZID anchor OP_RETURN — the on-chain master-key binding
         * (ANCHOR / ROTATE / REVOKE). The command byte selects how many
         * 32-byte key pushes follow, so the field count itself is
         * attacker-chosen. */
        struct zid_anchor_message msg;
        (void)zid_anchor_parse(payload, payload_len, &msg);
        break;
    }
    default:
        break;
    }

    return 0;
}
