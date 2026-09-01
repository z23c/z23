/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * network_crawler — the whole-network OBSERVATORY.
 *
 * The own-peer network_monitor only ever sees THIS node's handful of
 * connections; it structurally cannot answer "what does the ENTIRE reachable
 * ZClassic P2P network look like?" This service closes that gap Bitnodes-style:
 * a supervised worker walks the full local address table (addrman_get_addr),
 * opens SHORT-LIVED measurement sockets to a bounded, rate-limited batch of
 * addresses per round OUTSIDE the node's connman, performs only a version/verack
 * handshake, records {addr, onion-vs-clearnet, version, subver, services,
 * best_height, latency_us, reachable, last_probe_us}, then disconnects
 * immediately. It NEVER relays or syncs on these sockets.
 *
 * From that census it folds network-wide facts (reachable count, version
 * histogram, height distribution, onion/clearnet split) and a WHOLE-NETWORK
 * eclipse signal: if our connected peers cluster on a height that is a small
 * minority in the wider crawled network, that is an eclipse indicator the
 * own-peer monitor cannot see.
 *
 * ON BY DEFAULT (omniscience directive: the node obsesses about knowing the
 * whole network). It is opt-OUT: `-netcrawl=0` / `-nonetcrawl` or
 * ZCL_NETWORK_CRAWLER=0 fully disables the dialer. The rate limits below
 * (bounded probe batch on short-lived measurement sockets outside connman)
 * keep always-on cost tiny. When off, the supervised worker still registers
 * and idles (named degradation, never a boot failure).
 *
 * The per-address dialer is behind an injectable probe_fn seam so the census
 * fold is unit-tested hermetically with synthetic results — no real sockets.
 *
 * BOTH HALVES OF THE NETWORK ARE DIALED. A clearnet row is measured on a
 * short-lived TCP socket; an ONION row is measured through the embedded Tor
 * (tor_integration_fetch_onion_blocking — dynhost, no SOCKS). Onion dials cost
 * a circuit build, so they get their OWN budget: a per-round onion cap, a
 * separate (much smaller) onion concurrency cap, a separate per-dial timeout,
 * and a wall-clock budget for the whole onion phase. The clearnet phase always
 * runs FIRST and to completion, so slow onions can never starve it.
 *
 * NOT PROBED IS NOT UNREACHABLE. When Tor is absent (the default build links
 * vendor/tor_stub.c) or the onion budget ran out, the row is recorded with
 * outcome=NCRAWL_OUTCOME_NOT_PROBED and a reason — never as a failed dial.
 * A not-probed row is excluded from the reachable/unreachable fold and never
 * emits a census failure into the durable ledger, because a false negative
 * there would flow straight into peer reputation, which is worse than no data.
 *
 * ONION MEASUREMENT SEAM (stated, not hidden): the embedded Tor exposes
 * HTTP-over-onion via dynhost — there is no raw-stream/SOCKS path — so the
 * onion probe fetches /directory.json and treats "the service answered" as
 * reachable. An onion peer that serves P2P but no HTTP surface therefore reads
 * as measured-unreachable, not as a version handshake failure.
 */

#ifndef ZCL_SERVICES_NETWORK_CRAWLER_H
#define ZCL_SERVICES_NETWORK_CRAWLER_H

#include "net/netaddr.h"
#include "util/result.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct addr_man;
struct json_value;

/* ── Pedantic bounds (every one hard-capped) ─────────────────────────── */
enum {
    NCRAWL_MAX_CENSUS     = 1024, /* total bounded census-table cap */
    NCRAWL_MAX_PER_ROUND  = 64,   /* max addresses dialed per round */
    NCRAWL_MAX_CONCURRENT = 8,    /* HARD cap on concurrent in-flight dials */
    NCRAWL_MAX_VERSIONS   = 16,   /* distinct subver histogram buckets */
    NCRAWL_TOPN_VERSIONS  = 8,    /* reported top-N subver buckets */
    NCRAWL_ADDR_MAX       = 96,   /* addr string cap */
    NCRAWL_SUBVER_MAX     = 128,  /* trimmed subver cap */
    NCRAWL_ECLIPSE_MIN    = 4,    /* reachable nodes before eclipse can fire */
    NCRAWL_REASON_MAX     = 48,   /* short not-probed / failed-dial reason */
    /* Onion budget — bounded SEPARATELY from clearnet because a circuit build
     * costs seconds, not milliseconds. */
    NCRAWL_MAX_ONION_PER_ROUND  = 8, /* HARD cap on onion dials per round */
    NCRAWL_MAX_ONION_CONCURRENT = 2, /* HARD cap on concurrent onion dials */
};

#define NCRAWL_CONNECT_TIMEOUT_MS_DEFAULT   3000
#define NCRAWL_HANDSHAKE_TIMEOUT_MS_DEFAULT 4000
#define NCRAWL_ROUND_INTERVAL_SECS_DEFAULT  60
/* Per-onion-dial timeout and the wall-clock ceiling on the whole onion phase.
 * Worst case onion cost per round is budget + one in-flight dial timeout. */
#define NCRAWL_ONION_TIMEOUT_MS_DEFAULT      20000
#define NCRAWL_ONION_ROUND_BUDGET_MS_DEFAULT 25000

/* Did we actually MEASURE this address this round?
 *  MEASURED   — a dial ran; `reachable` is the verdict (true or false).
 *  NOT_PROBED — no dial was attempted (Tor absent, onion budget spent,
 *               unrenderable address). `reachable` is meaningless and MUST NOT
 *               be read as a negative. `reason` says why.
 * Zero-initializes to MEASURED so every pre-existing synthetic result keeps
 * exactly the meaning it had. */
enum ncrawl_probe_outcome {
    NCRAWL_OUTCOME_MEASURED   = 0,
    NCRAWL_OUTCOME_NOT_PROBED = 1,
};

/* One measured node in the census. reachable=false rows are retained too:
 * "we know this address, the last probe did not complete". */
struct ncrawl_probe_result {
    char     addr[NCRAWL_ADDR_MAX];
    bool     is_onion;
    bool     reachable;
    uint8_t  outcome;         /* enum ncrawl_probe_outcome */
    char     reason[NCRAWL_REASON_MAX];
    int32_t  version;
    char     subver[NCRAWL_SUBVER_MAX];
    uint64_t services;
    int64_t  best_height;
    int64_t  latency_us;
    int64_t  last_probe_us;   /* wall-unix secs of this probe */
};

struct ncrawl_version_bucket {
    char    subver[NCRAWL_SUBVER_MAX];
    int32_t count;
};

/* A folded snapshot of the whole reachable network. */
struct network_census_view {
    bool    ready;
    int64_t computed_at;
    int32_t probed;              /* census rows in the sample */
    int32_t reachable_count;     /* rows with reachable=true */
    int32_t onion_count;         /* reachable onion nodes */
    int32_t clearnet_count;      /* reachable clearnet nodes */

    /* MEASURED vs NOT PROBED. not_probed rows contribute to NEITHER the
     * reachable nor the unreachable side — they are the honest "we did not
     * look" bucket, kept out of every reachability judgement. */
    int32_t measured_count;
    int32_t not_probed_count;
    int32_t onion_measured_count;
    int32_t onion_not_probed_count;
    char    not_probed_reason[NCRAWL_REASON_MAX]; /* first non-empty reason */

    /* height distribution over reachable nodes advertising a best_height */
    int32_t heights_known;
    int64_t modal_height;        /* -1 if none */
    int32_t modal_height_count;
    int64_t max_height;          /* -1 if none */
    int64_t min_height;          /* -1 if none */
    int64_t height_spread;       /* max-min, 0 if <1 height known */

    /* version histogram (top-N, bounded) */
    int32_t num_versions;
    struct ncrawl_version_bucket versions[NCRAWL_MAX_VERSIONS];

    /* whole-network eclipse signal */
    bool    eclipse_suspected;
    int64_t own_modal_height;        /* our connected-peer modal (network_monitor) */
    int64_t network_modal_height;    /* == modal_height */
    int32_t network_count_at_own_modal;
};

/* ── Pure census fold (unit-testable with synthetic probe results) ──────
 * Deterministic; no clock/IO except stamping computed_at from the
 * caller-supplied now_unix. own_modal_height is our connected-peer modal
 * height (from network_monitor), or <0 if unknown. Feeding n > NCRAWL_MAX_CENSUS
 * clamps to the cap. */
void network_census_compute(const struct ncrawl_probe_result *r, int n,
                            int64_t own_modal_height, int64_t now_unix,
                            struct network_census_view *out);

/* ── Injectable dialer seam ─────────────────────────────────────────────
 * Fill *out for a single address (always set addr/is_onion/last_probe_us;
 * reachable + version/subver/... on a completed handshake). Return true if a
 * recordable result was produced, false only on invalid args/address. */
typedef bool (*ncrawl_probe_fn)(const struct net_address *addr,
                                int connect_timeout_ms,
                                int handshake_timeout_ms,
                                struct ncrawl_probe_result *out);

/* Default REAL dialer (network_crawler_probe.c). Two branches:
 *  - clearnet: a short-lived socket + version/verack handshake, then immediate
 *    disconnect, using connect_timeout_ms / handshake_timeout_ms as named.
 *  - onion: one HTTP-over-onion fetch through the embedded Tor. The crawler
 *    passes the ONION timeout in BOTH timeout slots for onion addresses (the
 *    seam signature is deliberately unchanged so every existing injected probe
 *    still compiles); this branch uses max(connect,handshake) as its ceiling.
 * Returns false only for an argument/address it cannot record at all. */
bool network_crawler_default_probe(const struct net_address *addr,
                                   int connect_timeout_ms,
                                   int handshake_timeout_ms,
                                   struct ncrawl_probe_result *out);

/* Render `addr` into its census key string: "<ip>:<port>" for clearnet, and
 * "<56 base32>.onion:<port>" for a Tor v3 address. The onion branch keeps
 * its own codec call (ncrawl_onion_hostname) because an UNRENDERABLE onion
 * must classify as a NOT_PROBED census row with a reason, while
 * net_service_to_string() would emit the "[torv3]" fallback placeholder.
 * Returns false when the address cannot be rendered (out is NUL-terminated
 * empty in that case). */
bool network_crawler_render_addr(const struct net_address *addr,
                                 char *out, size_t out_size);

/* True when the onion probe path can actually dial — i.e. the embedded Tor is
 * built in AND bootstrapped. False means every onion target is recorded
 * NOT_PROBED with a reason, never unreachable. */
bool network_crawler_onion_probe_available(void);

/* ── Runtime lifecycle ──────────────────────────────────────────────── */
struct network_crawler_config {
    bool enabled;               /* ON by default; -netcrawl=0 / ZCL_NETWORK_CRAWLER=0 opts out */
    int  round_interval_secs;
    int  max_per_round;
    int  max_concurrent;
    int  connect_timeout_ms;
    int  handshake_timeout_ms;
    /* Onion phase — its own budget so a dead onion cannot eat the round. */
    int  onion_max_per_round;    /* <= NCRAWL_MAX_ONION_PER_ROUND */
    int  onion_max_concurrent;   /* <= NCRAWL_MAX_ONION_CONCURRENT */
    int  onion_timeout_ms;       /* per-dial ceiling */
    int  onion_round_budget_ms;  /* wall-clock ceiling on the whole phase */
};
void network_crawler_config_defaults(struct network_crawler_config *cfg);

/* Start/stop the supervised crawler worker. addrman is the crawl seed (the full
 * local address table); it is only ever READ. When disabled the worker still
 * registers + idles. */
struct zcl_result network_crawler_start(const struct network_crawler_config *cfg,
                                        struct addr_man *addrman);
void network_crawler_stop(void);

/* Copy the latest folded census view. false until the first fold. */
bool network_crawler_get_view(struct network_census_view *out);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
bool network_crawler_dump_state_json(struct json_value *out, const char *key);

#ifdef ZCL_TESTING
void network_crawler_test_reset(void);
void network_crawler_test_set_probe_fn(ncrawl_probe_fn fn);
void network_crawler_test_set_own_modal(int64_t h);
/* Drive one synchronous probe round over addrs[0..n) using the (injected)
 * probe_fn, honoring the per-round + concurrency caps; ingest into the bounded
 * census and refold. Returns the number of addresses actually probed. */
int  network_crawler_test_probe_round(const struct net_address *addrs, int n);
int  network_crawler_test_census_count(void);
/* Read back one census row by its rendered address; false when absent. */
bool network_crawler_test_census_row(const char *addr,
                                     struct ncrawl_probe_result *out);
/* Override the onion sub-budget so the partition + budget-exhaustion paths are
 * provable without waiting on real circuits. */
void network_crawler_test_set_onion_limits(int per_round, int concurrent,
                                           int timeout_ms, int budget_ms);
/* Inject a folded census view (marks it ready) so the eclipse condition can be
 * unit-tested without a live crawl. */
void network_crawler_test_set_view(const struct network_census_view *v);
#endif

#endif /* ZCL_SERVICES_NETWORK_CRAWLER_H */
