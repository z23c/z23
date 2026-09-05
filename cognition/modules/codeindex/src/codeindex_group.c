/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_group — the group hierarchy: how a repo-relative path maps to a
 * navigator group (authority/context/shape or authority/modules/module) and
 * the fixed set of group nodes written into the store.
 *
 * The module and shape lists remain build-derived compatibility APIs used by
 * tests. Physical placement supplies the authority and context. */

#include "codeindex_priv.h"
#include "codeindex/codeindex_build.h"
#include "codeindex/codeindex_context.h"

#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

/* ── canonical taxonomy ───────────────────────────────────────────────────
 * The module list is not restated here. engine/composition/lib_module_order.def is the
 * one declaration of which modules exist; the Makefile derives its source
 * globs and -I flags from it, tools/lint/repo_shape.sh reads it, and this
 * pastes the same rows in as an X-macro. A hand-kept array here could disagree
 * with the build, and the failure would be quiet: an unlisted module's files
 * fall outside the navigator while everything still compiles.
 *
 * Order here is rank order, which only matters in that it sets the order
 * groups are emitted; membership is what this array is for. */

static const char *const k_lib_modules[] = {
#define LIB_MODULE(name_) name_,
#include "../../../../engine/composition/lib_module_order.def"
#undef LIB_MODULE
};

static const char *const k_app_shapes[] = {
    "conditions", "controllers", "jobs",
    "models", "services", "supervisors", "views",
};

static const char *const k_product_contexts[] = {
    "wallet", "explorer", "naming", "messaging", "market", "commons",
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

static bool starts_seg(const char *relpath, const char *seg)
{
    size_t n = strlen(seg);
    return strncmp(relpath, seg, n) == 0 && relpath[n] == '/';
}

/* Copy the first component_count components. */
static void leading_components(const char *relpath, size_t component_count,
                               char out[64])
{
    out[0] = '\0';
    const char *end = relpath;
    for (size_t i = 0; i < component_count; i++) {
        end = strchr(end, '/');
        if (!end) {
            end = relpath + strlen(relpath);
            break;
        }
        if (i + 1 < component_count) end++;
    }
    size_t length = (size_t)(end - relpath);
    if (length >= 64) length = 63;
    (void)snprintf(out, 64, "%.*s", (int)length, relpath);
}

void ci_group_for_path(const char *relpath, char out[64])
{
    out[0] = '\0';
    if (!relpath || !relpath[0]) return;

    const char *modules = strstr(relpath, "/modules/");
    if (modules) {
        const char *after = modules + strlen("/modules/");
        const char *end = strchr(after, '/');
        size_t length = end ? (size_t)(end - relpath) : strlen(relpath);
        if (length >= 64) length = 63;
        (void)snprintf(out, 64, "%.*s", (int)length, relpath);
        return;
    }
    if (starts_seg(relpath, "contexts")) {
        leading_components(relpath, 3, out);
        return;
    }
    if (starts_seg(relpath, "core") || starts_seg(relpath, "engine") ||
        starts_seg(relpath, "cognition") || starts_seg(relpath, "platform")) {
        leading_components(relpath, 2, out);
        return;
    }
    if (starts_seg(relpath, "tools")) {
        (void)snprintf(out, 64, "tools");
        return;
    }
    if (starts_seg(relpath, "tests")) {
        (void)snprintf(out, 64, "tests");
        return;
    }
    if (starts_seg(relpath, "docs")) {
        (void)snprintf(out, 64, "docs");
        return;
    }
    /* External C23 workspaces retain their conventional package layout. */
    if (starts_seg(relpath, "lib")) {
        leading_components(relpath, 2, out);
        return;
    }
    if (starts_seg(relpath, "app")) {
        const char *rest = relpath + strlen("app/");
        if (strchr(rest, '/')) leading_components(relpath, 2, out);
        else (void)snprintf(out, 64, "app");
        return;
    }
    if (starts_seg(relpath, "include")) {
        (void)snprintf(out, 64, "include");
        return;
    }
    if (starts_seg(relpath, "src")) {
        (void)snprintf(out, 64, "src");
        return;
    }
    if (starts_seg(relpath, "packages")) {
        (void)snprintf(out, 64, "packages");
        return;
    }
    if (starts_seg(relpath, "examples")) {
        (void)snprintf(out, 64, "examples");
        return;
    }
    (void)snprintf(out, 64, "root");
}

static bool module_group_is(const char *group, const char *module)
{
    const char *marker = strstr(group, "/modules/");
    return marker && strcmp(marker + strlen("/modules/"), module) == 0;
}

static bool group_ends_with(const char *group, const char *component)
{
    size_t group_length = strlen(group);
    size_t component_length = strlen(component);
    return group_length > component_length &&
           group[group_length - component_length - 1] == '/' &&
           strcmp(group + group_length - component_length, component) == 0;
}

/* ── canned purposes for the well-known top groups ───────────────────── */

const char *ci_group_purpose(const char *group)
{
    if (!group || !group[0]) return "";
    if (strcmp(group, "contexts") == 0) return "feature-first product rooms";
    if (strcmp(group, "core") == 0) return "sealed consensus core (params, chainparams, math, consensus)";
    if (strcmp(group, "engine") == 0) return "node composition, execution, and the one-writer reducer";
    if (strcmp(group, "cognition") == 0) return "stories, ontology, predicates, focus, heuristics, evidence, and experience";
    if (strcmp(group, "platform") == 0) return "ports and operating-system or infrastructure adapters";
    if (strcmp(group, "tools") == 0) return "dev/ops tooling and native command surfaces";
    if (strcmp(group, "tests") == 0) return "the canonical test runner, groups, fixtures, and specifications";
    if (strcmp(group, "docs") == 0) return "executable C23 examples embedded in maintained documentation";
    if (strcmp(group, "app") == 0) return "external C23 package application sources";
    if (strcmp(group, "include") == 0) return "external C23 package public headers";
    if (strcmp(group, "src") == 0) return "external C23 package implementation sources";
    if (strcmp(group, "lib") == 0) return "external C23 workspace modules";
    if (strcmp(group, "packages") == 0) return "reusable and independently buildable C23 packages";
    if (strcmp(group, "examples") == 0) return "small executable C23 usage examples";
    if (strcmp(group, "root") == 0) return "the source architecture";
    if (group_ends_with(group, "conditions")) return "shape: liveness/blocker conditions";
    if (group_ends_with(group, "controllers")) return "shape: REST + native + RPC request handlers";
    if (group_ends_with(group, "jobs")) return "shape: background jobs";
    if (group_ends_with(group, "models")) return "shape: ActiveRecord models";
    if (group_ends_with(group, "services")) return "shape: service objects (business logic)";
    if (group_ends_with(group, "supervisors")) return "shape: liveness supervisors";
    if (group_ends_with(group, "views")) return "shape: explorer/HTML/JSON views";
    if (group_ends_with(group, "reducer")) return "the only authoritative chain-state advancement room";
    if (group_ends_with(group, "ports")) return "interfaces required from the outside world";
    if (group_ends_with(group, "adapters")) return "platform implementations of ports";

    /* One line per reusable module in k_lib_modules[] above. */
    if (module_group_is(group, "base")) return "dependency sink: LOG_*/GUARD* macros, log-level filter, checked allocators, zcl_result (references nothing in-tree)";
    if (module_group_is(group, "bloom")) return "bloom filters + merkle proofs for lightweight block/tx filtering";
    if (module_group_is(group, "chain")) return "chain index primitives: MMB/MMR fast-sync proofs, UTXO-root ladder, snapshot loader";
    if (module_group_is(group, "codec")) return "allocation-free bounded reader/writer cursors over caller-owned buffers";
    if (module_group_is(group, "commons_demo")) return "standalone C23 Commons application core composed from base, codec, and JSON packages";
    if (module_group_is(group, "determinism")) return "verdict vectors and their digest, the four-bucket determinism classifier (deterministic, nondeterministic, timing-sensitive, unknown), and the determinism receipt (evidence, never permission)";
    if (module_group_is(group, "coins")) return "the UTXO set: coins view, undo data, compression, SHA3 UTXO commitment";
    if (module_group_is(group, "astro")) return "deterministic positional astronomy: one exact fixed-grid numeric type, CORDIC trigonometry over it, and reproducible birth-chart assembly";
    if (module_group_is(group, "core")) return "small consensus-adjacent primitives: amount, random, time-since-epoch helpers";
    if (module_group_is(group, "sha3")) return "scalar FIPS-202 SHA3/SHAKE primitives";
    if (module_group_is(group, "crypto")) return "hash/cipher/PoW primitives and batched SHA3 acceleration: SHA-2, Blake2, ChaCha20-Poly1305, Ed25519, Equihash";
    if (module_group_is(group, "crypto_registry")) return "singleton catalog of pluggable cryptographic verifier implementations";
    if (module_group_is(group, "encoding")) return "string encoding helpers: money strings, hex/bin string encodings";
    if (module_group_is(group, "engine")) return "engine-dispatch harness (pure half): vendor registry, request document, hardened response decoder, file envelope, key holder + redactor, and the gate-derived verdict";
    if (module_group_is(group, "event")) return "the in-process publish/subscribe event bus that decouples subsystems";
    if (module_group_is(group, "fingerprint")) return "behavioral fingerprints: fail-closed purity judgement, signature-derived call harnesses, shape-seeded input corpora";
    if (module_group_is(group, "framework")) return "app-shape platform glue: app_platform bootstrap + the typed-blocker condition contract";
    if (module_group_is(group, "health")) return "single in-process heartbeat/watchdog ring (replaces the old per-subsystem watchdogs)";
    if (module_group_is(group, "hotswap")) return "Tier-1 dev-only dlopen hot-swap loader for hotswap-eligible controller/handler TUs";
    if (module_group_is(group, "kernel")) return "service lifecycle kernel (init/start/stop/status ordering) + the native command registry";
    if (module_group_is(group, "install")) return "install front door: release-pin parsing, three-channel agreement, platform triple, DNS TXT wire (pure, no I/O)";
    if (module_group_is(group, "json")) return "minimal in-tree JSON value/parse/serialize library (no external deps)";
    if (module_group_is(group, "keys")) return "EC key material: private/public keys, bech32/base58 address key encoding";
    if (module_group_is(group, "metrics")) return "Prometheus-style in-process node metrics";
    if (module_group_is(group, "mining")) return "block template generation + the CPU miner loop";
    if (module_group_is(group, "net")) return "P2P networking: connman, peers, addrman, messages, Tor/onion, file market, fast sync";
    if (module_group_is(group, "noise")) return "secure-session transport: Noise handshake (NK/XX) + post-handshake AEAD record layer";
    if (module_group_is(group, "platform")) return "thin OS-portability wrappers: monotonic clock, RNG, time_t/timespec conversions";
    if (module_group_is(group, "policy")) return "mempool/relay fee policy (min relay fee, fee estimation)";
    if (module_group_is(group, "presentation")) return "bounded cross-platform native bitmap windows for QR, charts, Metaverse, and reviewed App output";
    if (module_group_is(group, "primitives")) return "consensus wire primitives: CBlock/CBlockHeader, CTransaction";
    if (module_group_is(group, "rpc")) return "JSON-RPC client/server plumbing: HTTP server, RPC dispatch, legacy zclassicd oracle client";
    if (module_group_is(group, "script")) return "Bitcoin Script interpreter, sig cache/encoding, HTLC + standard script templates";
    if (module_group_is(group, "session")) return "confined-agent broker: MVAP wire protocol, grant translation onto the metaverse evaluator, signed audit chain";
    if (module_group_is(group, "sim")) return "deterministic simnet: byzantine/cluster harnesses, seed-tape replay, HTLC contract overlay";
    if (module_group_is(group, "storage")) return "persistence layer: event log, coins/anchor/nullifier KV stores, block index, projections";
    if (module_group_is(group, "support")) return "page-locked allocations and the compatibility include for base-owned secure cleanse";
    if (module_group_is(group, "sync")) return "sync + snapshot-sync state machines (single owner of sync_state/sync_planner)";
    if (module_group_is(group, "util")) return "shared low-level utilities: logging, boot phase/progress, blockers, supervisor, safe_alloc";
    if (module_group_is(group, "validation")) return "consensus block/tx validation: connect_block, mempool accept, checkpoint, tx_verifier";
    if (module_group_is(group, "vcs")) return "in-binary ZVCS: source+binary snapshot/revert, sealed-core commitment guard";
    if (module_group_is(group, "wallet")) return "wallet key/persistence infra: HD keychain, BIP44, mnemonic, keystore, wallet DB";
    if (module_group_is(group, "sapling")) return "Sapling zk-SNARK primitives: Groth16 prover, Jubjub/BLS12-381, note encryption, circuits";
    if (module_group_is(group, "overlay")) return "overlay SDK: shared OP_RETURN codec + rebuildable-projection scaffold behind ZNAM/ZSLP/ZMSG/ZANC";
    if (module_group_is(group, "zslp")) return "Simple Ledger Protocol (SLP) token support encoded in OP_RETURN outputs";
    if (module_group_is(group, "zswap")) return "atomic ZSLP-token/ZCL P2P swaps: the canonical signed quote wire (zswap_quote.v1, pure codec) + the yardsale gossip-ad cache";
    if (module_group_is(group, "znam")) return "ZCL Names (ZNAM) on-chain name registry protocol (ENS-inspired)";
    if (module_group_is(group, "zanc")) return "ZCL Anchors (ZANC) on-chain SHA2/SHA3 software-package anchoring overlay";
    if (module_group_is(group, "zdir")) return "ZCL Directory (ZDIR) on-chain node directory overlay — .onion peer discovery folded from block history";
    if (module_group_is(group, "zid")) return "sovereign identity Phase 1: signed identity documents + blinded record keys (ed25519/SHA3, pure codec)";
    if (module_group_is(group, "codeindex")) return "the in-binary source-code navigator index: scan, store, query, the `code` CLI";
    if (module_group_is(group, "ontology")) return "canonical source-universe, contextual predicate-calculus objects, and bounded paraconsistent inference";
    if (module_group_is(group, "fleetfacts")) return "what the fleet has written down about itself — which executor handles which unit kind, what a train and a proof require, which failure signature names which trap — as typed rows over a closed vocabulary, asked by subject";
    if (module_group_is(group, "retrieval")) return "BM25 ranked retrieval over an in-memory corpus: an inverted index that answers \"which records are about this?\" in rank order rather than in match order";
    if (module_group_is(group, "chainlog")) return "a durable append-only log whose every frame is SHA3-linked to the one before it, so an edit anywhere shows up as a named first bad sequence number";
    if (module_group_is(group, "science")) return "the claim register for what makes a model write good C23: a claim is refused unless it names the metric, direction, effect floor and sample floor that could show it wrong, and status is derived from recorded trials rather than set";
    if (module_group_is(group, "receipt")) return "a proof receipt: one node's claim that a named test group reached a named verdict over an exactly identified source tree, in the fixed form it travels in";
    if (module_group_is(group, "territory")) return "generated per-module scorecard: what a module owns, what proves it (routed vs actually reached), what it depends on, where it is weak";
    if (module_group_is(group, "kpi")) return "the durable ledger of the numbers this build already produces: canonical frames appended to a hash-chained log, where a metric nobody could read is UNAVAILABLE and never 0";
    if (module_group_is(group, "metaverse")) return "sovereign digital property: property identity, action vocabulary, read-only per-kind catalog adapters, the pure grant/delegation rule evaluator, signed hash-chained receipts";

    if (strcmp(group, "platform/domain") == 0) return "pure framework-free encoding and platform value objects";
    if (strcmp(group, "contexts/wallet/domain") == 0) return "pure framework-free wallet key derivation and mnemonic math";

    /* Context and room descriptions remain useful when a room has no more
     * specific product prose yet. This is navigation metadata, not an
     * architecture authority or acceptance claim. */
    if (starts_seg(group, "contexts")) return "bounded product context or one of its feature-first rooms";
    if (group_ends_with(group, "modules")) return "reusable modules owned by this authority";
    if (starts_seg(group, "core")) return "sealed truth-layer room";
    if (starts_seg(group, "engine")) return "execution and composition room";
    if (starts_seg(group, "cognition")) return "software-understanding room";
    if (starts_seg(group, "platform")) return "outside-world boundary room";

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

    static const char *const authorities[] = {
        "core", "engine", "contexts", "cognition", "platform",
        "tools", "tests", "docs",
    };
    static const char *const external_roots[] = {
        "app", "include", "src", "lib", "packages", "examples",
    };
    static const char *const core_rooms[] = {
        "chainparams", "consensus", "math", "modules", "params",
    };
    static const char *const engine_rooms[] = {
        "application", "composition", "conditions", "controllers", "entry",
        "jobs", "models", "modules", "reducer", "services", "supervisors",
    };
    static const char *const cognition_rooms[] = {
        "controllers", "models", "modules", "services",
    };
    static const char *const platform_rooms[] = {
        "adapters", "deploy", "domain", "modules", "packaging", "ports",
    };
    static const char *const context_rooms[][12] = {
        {"controllers", "domain", "jobs", "models", "modules", "services", "views", NULL},
        {"controllers", "models", "modules", "views", NULL},
        {"controllers", "models", "modules", "services", NULL},
        {"controllers", "models", NULL},
        {"controllers", "models", "modules", "services", NULL},
        {"apps", "controllers", "corpus", "models", "modules", "packages", "services", "views", NULL},
    };

    if (!emit(s, "root", "root", "")) return false;
    for (size_t i = 0; i < sizeof(authorities) / sizeof(authorities[0]); i++)
        if (!emit(s, authorities[i], "authority", "root")) return false;
    for (size_t i = 0; i < sizeof(external_roots) / sizeof(external_roots[0]); i++)
        if (!emit(s, external_roots[i], "workspace", "root")) return false;

#define EMIT_ROOMS(authority_, rooms_)                                      \
    do {                                                                    \
        for (size_t room_i_ = 0;                                            \
             room_i_ < sizeof(rooms_) / sizeof((rooms_)[0]); room_i_++) {   \
            char room_path_[64];                                            \
            (void)snprintf(room_path_, sizeof(room_path_), "%s/%s",        \
                           (authority_), (rooms_)[room_i_]);                 \
            if (!emit(s, room_path_, "room", (authority_))) return false;  \
        }                                                                   \
    } while (0)

    EMIT_ROOMS("core", core_rooms);
    EMIT_ROOMS("engine", engine_rooms);
    EMIT_ROOMS("cognition", cognition_rooms);
    EMIT_ROOMS("platform", platform_rooms);
#undef EMIT_ROOMS

    for (size_t i = 0; i < sizeof(k_product_contexts) /
                           sizeof(k_product_contexts[0]); i++) {
        char context_path[64];
        (void)snprintf(context_path, sizeof(context_path), "contexts/%s",
                       k_product_contexts[i]);
        if (!emit(s, context_path, "context", "contexts")) return false;
        for (size_t j = 0; context_rooms[i][j]; j++) {
            char room_path[64];
            (void)snprintf(room_path, sizeof(room_path), "%s/%s",
                           context_path, context_rooms[i][j]);
            if (!emit(s, room_path, "room", context_path)) return false;
        }
    }

    /* Each build module keeps its own precise navigation group beneath the
     * authority declared by the context manifest. */
    size_t nmod = 0;
    const char *const *mods = ci_lib_modules(&nmod);
    for (size_t i = 0; i < nmod; i++) {
        char module_path[64], parent[64];
        if (!codeindex_module_group_path(mods[i], module_path))
            LOG_FAIL("codeindex", "module lacks architecture owner: %s", mods[i]);
        (void)snprintf(parent, sizeof(parent), "%s", module_path);
        char *slash = strrchr(parent, '/');
        if (!slash) LOG_FAIL("codeindex", "invalid module path: %s", module_path);
        *slash = '\0';
        if (!emit(s, module_path, "module", parent)) return false;
        (void)snprintf(module_path, sizeof(module_path), "lib/%s", mods[i]);
        if (!emit(s, module_path, "workspace-module", "lib")) return false;
    }
    for (size_t i = 0; i < sizeof(k_app_shapes) / sizeof(k_app_shapes[0]); i++) {
        char shape_path[64];
        (void)snprintf(shape_path, sizeof(shape_path), "app/%s", k_app_shapes[i]);
        if (!emit(s, shape_path, "workspace-shape", "app")) return false;
    }
    return true;
}
