/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * fuzz_snapshot — libFuzzer harness for the UTXO-snapshot / FlyClient
 * sync wire deserializers.
 *
 * A prior DoS audit READ these paths and confirmed the count prefixes
 * are cap-bounded (FC_MAX_SAMPLES, MMB_MAX_MOUNTAINS, and the manifest
 * range checks) before any array is walked. This harness proves those
 * bounds hold on adversarial bytes by feeding raw untrusted input
 * straight into the real deserialize entry points:
 *
 *   snapshot_manifest_parse       (zsnapoffer v2 manifest header)
 *   snapsync_parse_offer_params   (offer-params wrapper over the above)
 *   snapsync_parse_fc_response    (zfcproofs: sample/sibling/peak arrays,
 *                                  then the trailing utxo_root section)
 *
 * All three are pure wire parsers over a byte_stream — no sockets, no
 * disk, no globals — so each iteration is deterministic and self-
 * contained. The parsers memset their output up front; fc_response is
 * a large fixed-size struct (samples[FC_MAX_SAMPLES]) so it is heap-
 * allocated per iteration and freed. Runs with
 * -fsanitize=fuzzer,address,undefined under clang.
 */

#include "net/snapshot_sync_contract.h"
#include "net/flyclient.h"
#include "services/snapshot_manifest.h"
#include "core/serialize.h"
#include "chain/chainparams.h"
#include "util/safe_alloc.h"

#include <signal.h>
#include <stddef.h>
#include <stdint.h>

volatile sig_atomic_t g_shutdown_requested = 0;

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    chain_params_select(CHAIN_MAIN);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > (1u << 20))
        return 0;  /* libFuzzer convention: 0 means "keep going" */

    /* zsnapoffer v2 manifest header — fixed-layout scalar/hash reads
     * plus a strict trailing-bytes check. No dynamic allocation, but
     * the fixed reads must never run past `size`. */
    {
        struct byte_stream s;
        stream_init_from_data(&s, data, size);
        struct snapshot_manifest m;
        enum snapshot_manifest_result r = SNAPSHOT_MANIFEST_OK;
        (void)snapshot_manifest_parse(&m, &s, &r);
        stream_free(&s);
    }

    /* Offer-params wrapper: same wire bytes, exercises the public
     * entry the dispatcher calls (snapsync_parse_offer_params →
     * snapshot_manifest_parse → snapsync_params_from_manifest). */
    {
        struct byte_stream s;
        stream_init_from_data(&s, data, size);
        struct snapshot_offer_params params;
        (void)snapsync_parse_offer_params(&params, &s);
        stream_free(&s);
    }

    /* zfcproofs: num_samples (capped at FC_MAX_SAMPLES) then, per
     * sample, a leaf + MMB proof whose num_siblings / num_peaks are
     * capped at MMB_MAX_MOUNTAINS before their fixed-size arrays are
     * filled, then root_count (which must equal num_samples) and its
     * roots. This is the densest count-bounded path in the snapshot
     * family. fc_response is large (~256 KB) so heap-allocate it. */
    {
        struct byte_stream s;
        stream_init_from_data(&s, data, size);
        struct fc_response *resp =
            zcl_malloc(sizeof(*resp), "fuzz_fc_response");
        if (resp) {
            (void)snapsync_parse_fc_response(resp, &s);
            free(resp);
        }
        stream_free(&s);
    }

    return 0;
}
