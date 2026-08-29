/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_group — the group hierarchy: how a repo-relative path maps to a
 * navigator group (lib/<mod>, app/<shape>, core, tools, config, domain,
 * adapters) and the fixed set of group nodes written into the store.
 *
 * The LIB_MODULES and shape lists here are the in-code MIRROR of the
 * Makefile's LIB_MODULES variable and the seven app/ shape folders (the
 * eighth shape, Event, has no app/ folder — it is owned by
 * lib/event/ + lib/storage/event_log.c, see FRAMEWORK.md §3 row 7). A parity
 * test (test_codeindex, case 6) asserts they stay in sync. Keep them sorted
 * the way the Makefile lists them is NOT required — the parity test compares
 * as sets. k_domain_contexts[] mirrors the Makefile's DOMAIN_CONTEXTS the
 * same way, but is file-local (not exported) so it has no parity test yet. */

#include "codeindex_priv.h"
#include "codeindex/codeindex_build.h"

#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

/* ── canonical taxonomy ───────────────────────────────────────────────────
 * The lib module list is not restated here. config/lib_module_order.def is the
 * one declaration of which lib/ modules exist; the Makefile derives its source
 * globs and -I flags from it, tools/lint/repo_shape.sh reads it, and this
 * pastes the same rows in as an X-macro. A hand-kept array here could disagree
 * with the build, and the failure would be quiet: an unlisted module's files
 * fall into the catch-all `root` group and the navigator misfiles the whole
 * subtree while everything still compiles. That is exactly how lib/application
 * went missing from four separate copies of this taxonomy.
 *
 * Included by relative path because lib/ may not name config/ in an #include —
 * see tools/scripts/check_lib_layering.sh, which deliberately does not match
 * these data-only X-macro pastes (lib/hotswap does the same with
 * config/hotswap_eligible.def). It is a text paste, not a link edge: `nm` shows
 * no undefined config symbols in this object.
 *
 * Order here is rank order, which only matters in that it sets the order
 * groups are emitted; membership is what this array is for. */

static const char *const k_lib_modules[] = {
#define LIB_MODULE(name_) name_,
#include "../../../config/lib_module_order.def"
#undef LIB_MODULE
};

static const char *const k_app_shapes[] = {
    "conditions", "controllers", "jobs",
    "models", "services", "supervisors", "views",
};

/* mirrors the Makefile's DOMAIN_CONTEXTS = wallet encoding (case 8b in
 * check_group_purpose.sh cross-checks this list against the Makefile). */
static const char *const k_domain_contexts[] = {
    "encoding", "wallet",
};

const char *const *ci_lib_modules(size_t *count)
{
    if (count) *count = sizeof(k_lib_modules) / sizeof(k_lib_modules[0]);
    return k_lib_modules;
}

const char *const *ci_app_shapes(size_t *count)
{
    if (count) *count = sizeof(k_app_shapes) / sizeof(k_app_shapes[0]);
    return k_app_shapes;
}

/* ── path → group ────────────────────────────────────────────────────── */

/* Does relpath begin with "<seg>/"? */
static bool starts_seg(const char *relpath, const char *seg)
{
    size_t n = strlen(seg);
    return strncmp(relpath, seg, n) == 0 && relpath[n] == '/';
}

/* Copy the path component that follows "<top>/" into out (bounded). */
static void second_component(const char *relpath, const char *top, char out[64])
{
    out[0] = '\0';
    size_t n = strlen(top);
    if (strncmp(relpath, top, n) != 0 || relpath[n] != '/')
        return;
    const char *p = relpath + n + 1;
    const char *slash = strchr(p, '/');
    size_t len = slash ? (size_t)(slash - p) : strlen(p);
    if (len == 0) return;
    if (len > 62) len = 62;
    snprintf(out, 64, "%s/%.*s", top, (int)len, p);
}

void ci_group_for_path(const char *relpath, char out[64])
{
    out[0] = '\0';
    if (!relpath || !relpath[0]) return;

    if (starts_seg(relpath, "lib")) { second_component(relpath, "lib", out); return; }
    if (starts_seg(relpath, "app")) { second_component(relpath, "app", out); return; }
    if (starts_seg(relpath, "domain")) { second_component(relpath, "domain", out); return; }
    if (starts_seg(relpath, "core")) { snprintf(out, 64, "core"); return; }
    if (starts_seg(relpath, "config")) { snprintf(out, 64, "config"); return; }
    if (starts_seg(relpath, "tools")) { snprintf(out, 64, "tools"); return; }
    if (starts_seg(relpath, "adapters")) { snprintf(out, 64, "adapters"); return; }
    if (starts_seg(relpath, "ports")) { snprintf(out, 64, "ports"); return; }
    /* The Makefile carries APPLICATION_INCLUDES, so the build has always
     * known this root; every hand-written mirror of this list omitted it.
     * Without this arm the first file written under application/ lands in
     * the catch-all below and the orphan-placement gate reports it as
     * misplaced. */
    if (starts_seg(relpath, "application")) { snprintf(out, 64, "application"); return; }
    /* top-level file (src/main.c etc.) */
    snprintf(out, 64, "root");
}

/* ── canned purposes for the well-known top groups ───────────────────── */

const char *ci_group_purpose(const char *group)
{
    if (!group || !group[0]) return "";
    if (strcmp(group, "lib") == 0) return "reusable node libraries (one whole-program TU each)";
    if (strcmp(group, "app") == 0) return "the application shapes (Rails-like feature slices)";
    if (strcmp(group, "core") == 0) return "sealed consensus core (params, chainparams, math, consensus)";
    if (strcmp(group, "config") == 0) return "boot configuration + argv wiring";
    if (strcmp(group, "tools") == 0) return "dev/ops tooling and native command surfaces";
    if (strcmp(group, "domain") == 0) return "pure framework-free bounded contexts";
    if (strcmp(group, "adapters") == 0) return "hexagonal adapters implementing ports/";
    if (strcmp(group, "ports") == 0) return "hexagonal interface headers";
    if (strcmp(group, "application") == 0) return "clean-architecture use-case layer";
    if (strcmp(group, "root") == 0) return "top-level entry (src/main.c) and repo root files";
    if (strcmp(group, "lib/test") == 0) return "the canonical test runner, groups, fixtures, and specifications";
    if (strcmp(group, "app/conditions") == 0) return "shape: liveness/blocker conditions";
    if (strcmp(group, "app/controllers") == 0) return "shape: REST + native + RPC request handlers";
    if (strcmp(group, "app/jobs") == 0) return "shape: background jobs";
    if (strcmp(group, "app/models") == 0) return "shape: ActiveRecord models";
    if (strcmp(group, "app/services") == 0) return "shape: service objects (business logic)";
    if (strcmp(group, "app/supervisors") == 0) return "shape: liveness supervisors";
    if (strcmp(group, "app/views") == 0) return "shape: explorer/HTML/JSON views";

    /* lib/<mod> — one line per module in k_lib_modules[] above. */
    if (strcmp(group, "lib/base") == 0) return "dependency sink: LOG_*/GUARD* macros, log-level filter, checked allocators, zcl_result (references nothing in-tree)";
    if (strcmp(group, "lib/bloom") == 0) return "bloom filters + merkle proofs for lightweight block/tx filtering";
    if (strcmp(group, "lib/chain") == 0) return "chain index primitives: MMB/MMR fast-sync proofs, UTXO-root ladder, snapshot loader";
    if (strcmp(group, "lib/codec") == 0) return "allocation-free bounded reader/writer cursors over caller-owned buffers";
    if (strcmp(group, "lib/commons_demo") == 0) return "standalone C23 Commons application core composed from base, codec, and JSON packages";
    if (strcmp(group, "lib/coins") == 0) return "the UTXO set: coins view, undo data, compression, SHA3 UTXO commitment";
    if (strcmp(group, "lib/astro") == 0) return "deterministic positional astronomy: one exact fixed-grid numeric type, CORDIC trigonometry over it, and reproducible birth-chart assembly";
    if (strcmp(group, "lib/core") == 0) return "small consensus-adjacent primitives: amount, random, time-since-epoch helpers";
    if (strcmp(group, "lib/sha3") == 0) return "scalar FIPS-202 SHA3/SHAKE primitives";
    if (strcmp(group, "lib/crypto") == 0) return "hash/cipher/PoW primitives and batched SHA3 acceleration: SHA-2, Blake2, ChaCha20-Poly1305, Ed25519, Equihash";
    if (strcmp(group, "lib/crypto_registry") == 0) return "singleton catalog of pluggable cryptographic verifier implementations";
    if (strcmp(group, "lib/encoding") == 0) return "string encoding helpers: money strings, hex/bin string encodings";
    if (strcmp(group, "lib/event") == 0) return "the in-process publish/subscribe event bus that decouples subsystems";
    if (strcmp(group, "lib/framework") == 0) return "app-shape platform glue: app_platform bootstrap + the typed-blocker condition contract";
    if (strcmp(group, "lib/health") == 0) return "single in-process heartbeat/watchdog ring (replaces the old per-subsystem watchdogs)";
    if (strcmp(group, "lib/hotswap") == 0) return "Tier-1 dev-only dlopen hot-swap loader for hotswap-eligible controller/handler TUs";
    if (strcmp(group, "lib/kernel") == 0) return "service lifecycle kernel (init/start/stop/status ordering) + the native command registry";
    if (strcmp(group, "lib/json") == 0) return "minimal in-tree JSON value/parse/serialize library (no external deps)";
    if (strcmp(group, "lib/keys") == 0) return "EC key material: private/public keys, bech32/base58 address key encoding";
    if (strcmp(group, "lib/metrics") == 0) return "Prometheus-style in-process node metrics";
    if (strcmp(group, "lib/mining") == 0) return "block template generation + the CPU miner loop";
    if (strcmp(group, "lib/net") == 0) return "P2P networking: connman, peers, addrman, messages, Tor/onion, file market, fast sync";
    if (strcmp(group, "lib/noise") == 0) return "secure-session transport: Noise handshake (NK/XX) + post-handshake AEAD record layer";
    if (strcmp(group, "lib/platform") == 0) return "thin OS-portability wrappers: monotonic clock, RNG, time_t/timespec conversions";
    if (strcmp(group, "lib/policy") == 0) return "mempool/relay fee policy (min relay fee, fee estimation)";
    if (strcmp(group, "lib/presentation") == 0) return "bounded cross-platform native bitmap windows for QR, charts, Metaverse, and reviewed App output";
    if (strcmp(group, "lib/primitives") == 0) return "consensus wire primitives: CBlock/CBlockHeader, CTransaction";
    if (strcmp(group, "lib/rpc") == 0) return "JSON-RPC client/server plumbing: HTTP server, RPC dispatch, legacy zclassicd oracle client";
    if (strcmp(group, "lib/script") == 0) return "Bitcoin Script interpreter, sig cache/encoding, HTLC + standard script templates";
    if (strcmp(group, "lib/session") == 0) return "confined-agent broker: MVAP wire protocol, grant translation onto the metaverse evaluator, signed audit chain";
    if (strcmp(group, "lib/sim") == 0) return "deterministic simnet: byzantine/cluster harnesses, seed-tape replay, HTLC contract overlay";
    if (strcmp(group, "lib/storage") == 0) return "persistence layer: event log, coins/anchor/nullifier KV stores, block index, projections";
    if (strcmp(group, "lib/support") == 0) return "page-locked allocations and the compatibility include for base-owned secure cleanse";
    if (strcmp(group, "lib/sync") == 0) return "sync + snapshot-sync state machines (single owner of sync_state/sync_planner)";
    if (strcmp(group, "lib/util") == 0) return "shared low-level utilities: logging, boot phase/progress, blockers, supervisor, safe_alloc";
    if (strcmp(group, "lib/validation") == 0) return "consensus block/tx validation: connect_block, mempool accept, checkpoint, tx_verifier";
    if (strcmp(group, "lib/vcs") == 0) return "in-binary ZVCS: source+binary snapshot/revert, sealed-core commitment guard";
    if (strcmp(group, "lib/wallet") == 0) return "wallet key/persistence infra: HD keychain, BIP44, mnemonic, keystore, wallet DB";
    if (strcmp(group, "lib/sapling") == 0) return "Sapling zk-SNARK primitives: Groth16 prover, Jubjub/BLS12-381, note encryption, circuits";
    if (strcmp(group, "lib/overlay") == 0) return "overlay SDK: shared OP_RETURN codec + rebuildable-projection scaffold behind ZNAM/ZSLP/ZMSG/ZANC";
    if (strcmp(group, "lib/zslp") == 0) return "Simple Ledger Protocol (SLP) token support encoded in OP_RETURN outputs";
    if (strcmp(group, "lib/zswap") == 0) return "atomic ZSLP-token/ZCL P2P swaps: the canonical signed quote wire (zswap_quote.v1, pure codec) + the yardsale gossip-ad cache";
    if (strcmp(group, "lib/znam") == 0) return "ZCL Names (ZNAM) on-chain name registry protocol (ENS-inspired)";
    if (strcmp(group, "lib/zanc") == 0) return "ZCL Anchors (ZANC) on-chain SHA2/SHA3 software-package anchoring overlay";
    if (strcmp(group, "lib/zdir") == 0) return "ZCL Directory (ZDIR) on-chain node directory overlay — .onion peer discovery folded from block history";
    if (strcmp(group, "lib/zid") == 0) return "sovereign identity Phase 1: signed identity documents + blinded record keys (ed25519/SHA3, pure codec)";
    if (strcmp(group, "lib/codeindex") == 0) return "the in-binary source-code navigator index: scan, store, query, the `code` CLI";
    if (strcmp(group, "lib/metaverse") == 0) return "sovereign digital property: property identity, action vocabulary, read-only per-kind catalog adapters, the pure grant/delegation rule evaluator, signed hash-chained receipts";

    /* domain/<ctx> — one line per bounded context in k_domain_contexts[] above. */
    if (strcmp(group, "domain/encoding") == 0) return "pure framework-free base58/bech32 address encoding (no clock/RNG/IO)";
    if (strcmp(group, "domain/wallet") == 0) return "pure framework-free HD key derivation + mnemonic math (no clock/RNG/IO)";

    return "";
}

/* ── emit the fixed hierarchy into an open txn ───────────────────────── */

static bool emit(struct ci_store *s, const char *path, const char *kind,
                 const char *parent)
{
    struct ci_group g;
    memset(&g, 0, sizeof(g));
    snprintf(g.path, sizeof(g.path), "%s", path);
    snprintf(g.kind, sizeof(g.kind), "%s", kind);
    snprintf(g.parent, sizeof(g.parent), "%s", parent);
    snprintf(g.purpose, sizeof(g.purpose), "%s", ci_group_purpose(path));
    return ci_store_put_group(s, &g);
}

bool ci_group_emit_all(struct ci_store *s)
{
    if (!s) LOG_FAIL("codeindex", "null store to emit_all");

    /* top-level roots */
    if (!emit(s, "root", "root", "")) return false;
    if (!emit(s, "lib", "root", "root")) return false;
    if (!emit(s, "app", "root", "root")) return false;
    if (!emit(s, "core", "core", "root")) return false;
    if (!emit(s, "config", "config", "root")) return false;
    if (!emit(s, "tools", "tools", "root")) return false;
    if (!emit(s, "domain", "root", "root")) return false;
    if (!emit(s, "adapters", "adapters", "root")) return false;
    if (!emit(s, "ports", "ports", "root")) return false;
    if (!emit(s, "application", "application", "root")) return false;

    /* lib/<mod> */
    size_t nmod = 0;
    const char *const *mods = ci_lib_modules(&nmod);
    for (size_t i = 0; i < nmod; i++) {
        char path[64];
        snprintf(path, sizeof(path), "lib/%s", mods[i]);
        if (!emit(s, path, "lib", "lib")) return false;
    }
    if (!emit(s, "lib/test", "test", "lib")) return false;

    /* app/<shape> */
    size_t nsh = 0;
    const char *const *shapes = ci_app_shapes(&nsh);
    for (size_t i = 0; i < nsh; i++) {
        char path[64];
        snprintf(path, sizeof(path), "app/%s", shapes[i]);
        if (!emit(s, path, "app-shape", "app")) return false;
    }

    /* domain/<ctx> */
    size_t ndc = sizeof(k_domain_contexts) / sizeof(k_domain_contexts[0]);
    for (size_t i = 0; i < ndc; i++) {
        char path[64];
        snprintf(path, sizeof(path), "domain/%s", k_domain_contexts[i]);
        if (!emit(s, path, "domain-context", "domain")) return false;
    }
    return true;
}
