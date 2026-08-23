/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_auto_install_bundle.c — the BOOT WIRINGS around the non-terminal install
 * engine (config/src/consensus_state_install_runtime.c). Contract in
 * config/consensus_state_install_runtime.h.
 *
 *   1b. Zero-flag cold-boot autodetect of a complete-state bundle under
 *       <datadir>/bundles/<name>.sqlite, installed BEFORE the transparent-only
 *       from-anchor path (which would leave shielded state empty → the
 *       anchor_backfill_gap wedge).
 *   1c. A durable "install-on-next-boot" request, modeled EXACTLY on the proven
 *       boot_auto_refold_* self-respawn pattern: a bounded, fsync-durable
 *       request boot consumes and runs through the same installer, then clears.
 *       This is the entry point the shielded-gap self-heal (Move 2) arms; Move 2
 *       itself is deliberately NOT wired here.
 *
 * Plus boot_select_state_source — the app_init seam composing the three booleans
 * (auto_installed_bundle / consumed_auto_refold / do_from_anchor) that select the
 * boot's state source, kept here so app_init stays a thin caller. A complete
 * install SUPERSEDES the transparent-only from-anchor reset. Fail-closed
 * everywhere; a durable marker prevents re-installing over sovereign state. */

#include "config/consensus_state_install_runtime.h"

#include "config/boot.h"                       /* app_context, boot_refold_body_span_contiguous,
                                                 * boot_load_verify_snapshot_eligible, active_chain_* */
#include "config/boot_bundle_fetch.h"          /* THE WELD: download-before-autodetect */
#include "config/boot_header_seed_import.h"    /* headers-as-artifact in-process import */
#include "config/boot_consensus_bundle_marker.h"
#include "net/checkpoint_header_fetch.h"       /* pre-arm compiled-checkpoint capture */
#include "conditions/no_state_source.h"        /* LOUD no-state-source signage */
#include "jobs/reducer_frontier.h"             /* reducer_frontier_provable_tip_cached */
#include "storage/boot_auto_refold.h"          /* A1: consume the escalator's armed refold */
#include "storage/progress_store.h"            /* progress_store_db */
#include "util/log_macros.h"
#include "util/safe_alloc.h"                   /* zcl_malloc */
#include "validation/chainstate.h"             /* active_chain_height */
#include "validation/main_state.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ICB_SUBSYS "install_consensus_bundle"

/* ── 1b — Autodetect a complete-state bundle under <datadir>/bundles/ ───────── */

/* Parse the height out of a canonical "consensus-state-bundle-<N>.sqlite" name,
 * or -1 for any other *.sqlite name. Lets the freshest-selection sort NUMERICALLY
 * by height rather than lexicographically (which mis-orders un-padded heights,
 * e.g. "...-9.sqlite" > "...-3056758.sqlite"). Pure. */
static long icb_bundle_height(const char *name)
{
    static const char PFX[] = "consensus-state-bundle-";
    static const char SFX[] = ".sqlite";
    size_t pl = sizeof(PFX) - 1, sl = sizeof(SFX) - 1, nl = strlen(name);
    if (nl <= pl + sl || strncmp(name, PFX, pl) != 0 ||
        strcmp(name + nl - sl, SFX) != 0)
        return -1;
    const char *d = name + pl;
    size_t dcount = nl - pl - sl;
    if (dcount == 0 || dcount >= 19)
        return -1;
    long h = 0;
    for (size_t i = 0; i < dcount; i++) {
        if (d[i] < '0' || d[i] > '9')
            return -1;
        h = h * 10 + (d[i] - '0');
    }
    return h;
}

char *boot_autodetect_consensus_bundle(const char *datadir)
{
    if (!datadir || !datadir[0])
        return NULL;

    /* Never re-install over already-sovereign state. */
    if (boot_consensus_bundle_marker_exists(datadir))
        return NULL;

    char dirpath[PATH_MAX];
    int dn = snprintf(dirpath, sizeof(dirpath), "%s/bundles", datadir);
    if (dn < 0 || (size_t)dn >= sizeof(dirpath))
        return NULL;

    DIR *d = opendir(dirpath);
    if (!d)
        return NULL; /* no bundles/ directory → nothing to auto-install */

    static const char SFX[] = ".sqlite";
    const size_t slen = sizeof(SFX) - 1;
    char best_name[256] = {0};
    long best_h = -1;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        const char *nm = ent->d_name;
        size_t len = strlen(nm);
        if (len <= slen || len >= sizeof(best_name))
            continue;
        if (strcmp(nm + len - slen, SFX) != 0)
            continue;
        /* Never-stuck: a prior boot that failed installing THIS bundle wrote a
         * sibling "<name>.failed" marker. Skip such a bundle so a bad /
         * incompatible / contained bundle degrades to normal boot on the next
         * (systemd Restart=always) boot instead of retrying forever — no human
         * needed to delete it. */
        char failp[PATH_MAX];
        int fpn = snprintf(failp, sizeof(failp), "%s/%s.failed", dirpath, nm);
        if (fpn > 0 && (size_t)fpn < sizeof(failp) && access(failp, F_OK) == 0)
            continue;
        /* FRESHEST wins, NUMERICALLY by parsed height (not lexicographically —
         * un-padded heights lex-mis-sort). A canonical bundle (height >= 0)
         * always beats a non-canonical *.sqlite (height -1); among canonical
         * names the higher height wins; ties / two non-canonical names break
         * lexicographically for stable determinism. */
        long h = icb_bundle_height(nm);
        bool take;
        if (best_name[0] == '\0')
            take = true;
        else if (h != best_h)
            take = h > best_h;
        else
            take = strcmp(nm, best_name) > 0;
        if (take) {
            snprintf(best_name, sizeof(best_name), "%s", nm);
            best_h = h;
        }
    }
    closedir(d);

    if (best_name[0] == '\0')
        return NULL; /* no installable *.sqlite bundle present */

    char *outp = zcl_malloc(PATH_MAX, "autodetect_consensus_bundle");
    if (!outp)
        return NULL;
    int on = snprintf(outp, PATH_MAX, "%s/%s", dirpath, best_name);
    if (on < 0 || on >= PATH_MAX) {
        free(outp);
        return NULL;
    }
    return outp;
}

/* Write a sibling "<bundle_path>.failed" never-stuck marker (best-effort). */
static void csir_write_failed_marker(const char *bundle_path)
{
    char failp[PATH_MAX];
    int n = snprintf(failp, sizeof(failp), "%s.failed", bundle_path);
    if (n < 0 || (size_t)n >= sizeof(failp))
        return;
    int fd = open(failp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        LOG_WARN(ICB_SUBSYS, "could not write never-stuck marker %s: %s", failp,
                 strerror(errno));
        return;
    }
    (void)close(fd);
}

/* Clear a stale "<bundle_path>.failed" marker after the bundle installed
 * successfully: without this, an earlier failed attempt at the same path
 * (e.g. a watchdog-killed boot) permanently excludes the now-GOOD bundle
 * from autodetect on every later scan (boot_autodetect_consensus_bundle
 * skips marked bundles) — observed live 2026-07-27 on the canonical
 * datadir (marker 04:28, good bundle 05:37). Best-effort: a remove()
 * failure is loud but non-fatal, the install itself is durable.
 * Contract: config/consensus_state_install_runtime.h. */
void boot_auto_install_clear_failed_marker(const char *bundle_path)
{
    if (!bundle_path || !*bundle_path)
        return;
    char failp[PATH_MAX];
    int n = snprintf(failp, sizeof(failp), "%s.failed", bundle_path);
    if (n < 0 || (size_t)n >= sizeof(failp))
        return;
    if (remove(failp) != 0 && errno != ENOENT)
        LOG_WARN(ICB_SUBSYS, "could not clear stale never-stuck marker %s: %s",
                 failp, strerror(errno));
}

/* ── 1c — Durable "install-on-next-boot" request (mirror of boot_auto_refold_*) */

static void ibr_path(const char *datadir, char *out, size_t n)
{
    snprintf(out, n, "%s/install_bundle_request", datadir);
}

/* Read the on-disk (attempts, path). Returns true iff a well-formed request was
 * read (a numeric attempts line + a non-empty path line). On any miss *attempts
 * is 0 and bundle_out is empty. When bundle_out is provided the path must fit in
 * cap (a would-truncate path fails closed). */
static bool ibr_read(const char *path, int *attempts, char *bundle_out,
                     size_t cap)
{
    *attempts = 0;
    if (bundle_out && cap)
        bundle_out[0] = '\0';
    FILE *r = fopen(path, "r");
    if (!r)
        return false;
    int a = 0;
    if (fscanf(r, "%d", &a) != 1) {
        fclose(r);
        return false;
    }
    int sep = fgetc(r); /* consume the single separating newline */
    if (sep != '\n') {
        fclose(r);
        return false;
    }
    char buf[PATH_MAX];
    if (!fgets(buf, sizeof(buf), r)) {
        fclose(r);
        return false;
    }
    fclose(r);
    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        buf[--len] = '\0';
    if (len == 0)
        return false; /* a request must carry its bundle path */
    if (bundle_out) {
        if (len >= cap)
            return false;
        memcpy(bundle_out, buf, len + 1);
    }
    *attempts = a;
    return true;
}

/* fsync-durable write of "<attempts>\n<bundle_path>\n". Returns true on success. */
static bool ibr_write(const char *datadir, const char *path, int attempts,
                      const char *bundle_path)
{
    char buf[PATH_MAX + 32];
    int len = snprintf(buf, sizeof(buf), "%d\n%s\n", attempts, bundle_path);
    if (len < 0 || len >= (int)sizeof(buf))
        return false;

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        LOG_WARN(ICB_SUBSYS, "install_bundle_request: open(%s) failed: %s", path,
                 strerror(errno));
        return false;
    }
    ssize_t w = write(fd, buf, (size_t)len);
    int sync_rc = fsync(fd); /* the budget MUST survive a crash mid-install */
    int close_rc = close(fd);
    if (w != (ssize_t)len || sync_rc != 0 || close_rc != 0) {
        LOG_WARN(ICB_SUBSYS, "install_bundle_request: write/fsync(%s) failed", path);
        return false;
    }
    /* fsync the directory so the file's existence is durable across a crash. */
    int dfd = open(datadir, O_RDONLY | O_DIRECTORY);
    if (dfd >= 0) {
        (void)fsync(dfd);
        close(dfd);
    }
    return true;
}

int boot_install_bundle_request(const char *datadir, const char *bundle_path)
{
    if (!datadir || !datadir[0] || !bundle_path || !bundle_path[0])
        return 0;
    if (strchr(bundle_path, '\n')) /* one line only — the codec is line-oriented */
        return 0;

    char path[512];
    ibr_path(datadir, path, sizeof(path));

    int cur_attempts = 0;
    char cur_bundle[PATH_MAX];
    bool have = ibr_read(path, &cur_attempts, cur_bundle, sizeof(cur_bundle));

    /* TERMINAL already written: the budget was exhausted and the operator paged.
     * Do NOT re-arm — that is exactly the unbounded crash-loop this exists to
     * prevent. */
    if (have && cur_attempts == BOOT_INSTALL_BUNDLE_TERMINAL)
        return BOOT_INSTALL_BUNDLE_TERMINAL;

    /* Already armed (not terminal): leave it — attempts bump at consume time so a
     * re-arming caller cannot inflate the budget. Report the current count. */
    if (have && cur_attempts >= 0)
        return cur_attempts > 0 ? cur_attempts : 1;

    /* Fresh arm: attempts=0 (armed, not yet attempted by any boot). */
    if (!ibr_write(datadir, path, 0, bundle_path))
        return 0;
    return 1;
}

bool boot_install_bundle_pending(const char *datadir)
{
    if (!datadir)
        return false;
    char path[512];
    ibr_path(datadir, path, sizeof(path));
    if (access(path, F_OK) != 0)
        return false;
    int a = 0;
    char b[PATH_MAX];
    if (ibr_read(path, &a, b, sizeof(b)) && a == BOOT_INSTALL_BUNDLE_TERMINAL)
        return false; /* terminal: present-but-not-pending */
    return true;
}

bool boot_install_bundle_consume(const char *datadir, char *out_path,
                                 size_t out_cap)
{
    if (out_path && out_cap)
        out_path[0] = '\0';
    if (!datadir || !out_path || !out_cap)
        return false;

    char path[512];
    ibr_path(datadir, path, sizeof(path));

    int attempts = 0;
    char bundle[PATH_MAX];
    if (!ibr_read(path, &attempts, bundle, sizeof(bundle)))
        return false; /* no / malformed request */
    if (attempts == BOOT_INSTALL_BUNDLE_TERMINAL)
        return false; /* budget already spent */

    if (attempts >= BOOT_INSTALL_BUNDLE_MAX) {
        /* Budget exhausted: persist the terminal marker (do NOT delete — a delete
         * would let the next boot re-arm a fresh count and loop) and refuse so the
         * node boots normally + the escalator/operator sees it. */
        (void)ibr_write(datadir, path, BOOT_INSTALL_BUNDLE_TERMINAL, bundle);
        LOG_WARN(ICB_SUBSYS,
                 "install-on-next-boot request for %s exhausted the bounded budget "
                 "(max=%d) — marking TERMINAL, booting normally", bundle,
                 BOOT_INSTALL_BUNDLE_MAX);
        return false;
    }

    if (strlen(bundle) >= out_cap)
        return false; /* caller buffer too small — fail closed */

    /* Count this boot's attempt BEFORE running the install, so a FATAL-exit mid
     * install still burns the budget. */
    if (!ibr_write(datadir, path, attempts + 1, bundle))
        return false;
    snprintf(out_path, out_cap, "%s", bundle);
    return true;
}

void boot_install_bundle_clear(const char *datadir)
{
    if (!datadir)
        return;
    char path[512];
    ibr_path(datadir, path, sizeof(path));
    (void)remove(path);
}

/* Reuse boot_refold_body_span_contiguous: after a successful install, if the
 * local header chain already extends above the installed height (the Move 2
 * self-heal case on an already-synced node), NAME any body gap in the
 * fold-forward span so the reducer's body-fetch fills it rather than the fold
 * silently stalling. Non-fatal — the install is durable; this only raises the
 * typed blocker refold.body_gap so the stall is never silent. Extracted as its
 * own entry point (contract in consensus_state_install_runtime.h) so the
 * "catch the tail" wiring is directly unit-testable without a full bundle
 * install. */
void boot_post_install_fold_span_check(struct main_state *ms,
                                       int32_t installed_height)
{
    if (!ms || installed_height < 0)
        return;
    int32_t resume_target = (int32_t)active_chain_height(&ms->chain_active);
    if (resume_target <= installed_height)
        return; /* fresh install: no local advance yet — body_fetch resumes at
                  * installed_height+1 and the tail arrives via normal P2P */
    int32_t first_missing = -1;
    if (!boot_refold_body_span_contiguous(ms, installed_height, resume_target,
                                          &first_missing, /*raise_blocker=*/true))
        LOG_WARN(ICB_SUBSYS,
                 "post-install fold span (%d..%d] has a missing body at "
                 "h=%d — named blocker refold.body_gap raised; the "
                 "reducer's body-fetch fills it before the fold advances",
                 installed_height, resume_target, first_missing);
}

/* ── The 1b + 1c orchestrator ──────────────────────────────────────────────── */

bool boot_maybe_auto_install_consensus_bundle(struct node_db *ndb,
                                              struct main_state *ms,
                                              const char *datadir)
{
    if (!datadir || !datadir[0])
        return false;

    /* Never re-install over already-sovereign state. */
    if (boot_consensus_bundle_marker_exists(datadir))
        return false;

    bool installed = false;
    int32_t installed_height = -1;

    /* (1c) A durable install-on-next-boot request (the Move 2 self-heal) takes
     * precedence over the passive autodetect. Consume bumps the bounded attempt
     * count so a persistently-failing bundle degrades to a normal boot instead
     * of crash-looping. */
    char req_path[PATH_MAX];
    if (boot_install_bundle_pending(datadir) &&
        boot_install_bundle_consume(datadir, req_path, sizeof(req_path))) {
        struct consensus_state_install_runtime_result rr;
        struct zcl_result r =
            consensus_state_install_from_bundle(ndb, ms, req_path, datadir, &rr);
        if (r.ok) {
            boot_install_bundle_clear(datadir);
            boot_auto_install_clear_failed_marker(req_path);
            installed = true;
            installed_height = rr.height;
            LOG_INFO(ICB_SUBSYS,
                     "install-on-next-boot request installed %s (H*=%d)", req_path,
                     rr.hstar);
        } else if (rr.state_installed) {
            /* Landed durably but a post-install step failed. Do NOT clear the
             * request or fall through to a wipe: the swapped state is on disk, a
             * retry re-runs activate+invalidation (idempotent), the bounded budget
             * caps retries, and the boot loader's own Sapling/coins gates are the
             * backstop. Never-silent. */
            LOG_ERROR(ICB_SUBSYS,
                      "install-on-next-boot request for %s landed durably but a "
                      "post-install step failed (%s) — retrying under the bounded "
                      "budget on the next boot", req_path, rr.reason);
        } else if (rr.retriable_headers_not_ready) {
            /* Defensive: the retry condition only arms this request once the
             * header chain has reached the checkpoint, and the header chain is
             * durable, so a consume should find headers ready. If it does not
             * (a torn/rewound header index), the bounded consume budget still
             * caps the retries — just log the wait rather than a hard error. */
            LOG_INFO(ICB_SUBSYS,
                     "install-on-next-boot request for %s deferred: %s",
                     req_path, rr.reason);
        } else {
            LOG_ERROR(ICB_SUBSYS,
                      "install-on-next-boot request for %s did not install: %s",
                      req_path, rr.reason);
        }
    }

    /* (1b) Passive autodetect of a <datadir>/bundles/<name>.sqlite starter bundle. */
    if (!installed) {
        char *auto_bundle = boot_autodetect_consensus_bundle(datadir);
        if (auto_bundle) {
            struct consensus_state_install_runtime_result rr;
            struct zcl_result r = consensus_state_install_from_bundle(
                ndb, ms, auto_bundle, datadir, &rr);
            if (r.ok) {
                installed = true;
                installed_height = rr.height;
                boot_auto_install_clear_failed_marker(auto_bundle);
                LOG_INFO(ICB_SUBSYS, "autodetected consensus bundle installed %s "
                                     "(H*=%d)", auto_bundle, rr.hstar);
            } else if (rr.state_installed) {
                LOG_ERROR(ICB_SUBSYS,
                          "autodetected bundle %s landed durably but a "
                          "post-install step failed (%s) — retrying on the next "
                          "boot (not marked .failed: the state is on disk)",
                          auto_bundle, rr.reason);
            } else if (rr.retriable_headers_not_ready) {
                /* RETRIABLE WAIT (fresh boot / mid-header-sync): the validated
                 * header chain has not yet reached the checkpoint height. The
                 * bundle is GOOD — the node has not caught up — so do NOT mark
                 * .failed. It is re-detected on the next boot, and the
                 * checkpoint_bundle_install_ready condition arms the install the
                 * moment the header chain reaches the checkpoint this session. */
                LOG_INFO(ICB_SUBSYS,
                         "autodetected bundle %s deferred (NOT marked .failed): "
                         "%s", auto_bundle, rr.reason);
            } else {
                /* Genuine pre-activate refusal (bad / incompatible / contained
                 * bundle): mark .failed so the next boot degrades to normal
                 * behavior (never-stuck). */
                csir_write_failed_marker(auto_bundle);
                LOG_ERROR(ICB_SUBSYS,
                          "autodetected bundle %s did not install (marked .failed "
                          "→ normal boot next time): %s", auto_bundle, rr.reason);
            }
            free(auto_bundle);
        }
    }

    /* Post-install "catch the tail" check — see boot_post_install_fold_span_
     * check's contract above / in the header for the full rationale. */
    if (installed)
        boot_post_install_fold_span_check(ms, installed_height);

    return installed;
}

/* ── LOUD no-state-source signage helpers ──────────────────────────────────── */

/* True iff this datadir has no meaningful chain state yet — a genesis-only (or
 * empty) active-chain window, so the reducer would fold from genesis. Reads the
 * canonical active_chain_height (which consults the durable tip_finalize frontier
 * when the progress store is open), so a WARM reboot of an already-synced node
 * reports its real height and is NOT mistaken for a fresh, sourceless boot. */
static bool nss_no_meaningful_chain_state(struct main_state *ms)
{
    if (!ms)
        return true;
    return active_chain_height(&ms->chain_active) <= 0;
}

/* True iff an installable *.sqlite bundle is still staged (a deferred install is
 * a PENDING state source — checkpoint_bundle_install_ready owns that case). */
static bool nss_bundle_staged(const char *datadir)
{
    char *b = boot_autodetect_consensus_bundle(datadir);
    if (!b)
        return false;
    free(b);
    return true;
}

/* True iff a prior boot marked a staged bundle <name>.sqlite.failed. */
static bool nss_failed_bundle_present(const char *datadir)
{
    char dirpath[PATH_MAX];
    int n = snprintf(dirpath, sizeof(dirpath), "%s/bundles", datadir);
    if (n < 0 || (size_t)n >= sizeof(dirpath))
        return false;
    DIR *d = opendir(dirpath);
    if (!d)
        return false;
    static const char SFX[] = ".failed";
    const size_t slen = sizeof(SFX) - 1;
    bool found = false;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        size_t len = strlen(ent->d_name);
        if (len > slen && strcmp(ent->d_name + len - slen, SFX) == 0) {
            found = true;
            break;
        }
    }
    closedir(d);
    return found;
}

/* Best-effort classification of WHY no state source landed, from observable
 * datadir state (the rich per-seed fetch outcome is Lane 2's to plumb; this
 * distinguishes what the boot seam can see today). */
static void nss_classify(struct app_context *ctx,
                         struct no_state_source_facts *out)
{
    memset(out, 0, sizeof(*out));

    if (!boot_bundle_fetch_should_run(ctx->datadir, ctx)) {
        /* Not eligible — opt-out (-nofilesync / ZCL_NO_BUNDLE_FETCH). */
        out->fetch = NO_STATE_SOURCE_FETCH_SKIPPED;
    } else if (boot_bundle_fetch_seed_count(ctx) == 0) {
        /* Eligible, but the seed set assembled to ZERO peers, so the fetch was
         * never ATTEMPTED. boot_bundle_fetch_should_run does not consult the
         * seed set, so without this branch a structurally-off fetch reported
         * `no_seed` — indistinguishable from "seeds were contacted and none
         * served a usable manifest", which is what made the 2026-07-27 bare
         * cold start read as a network/discovery problem when it was a wiring
         * one. */
        out->fetch = NO_STATE_SOURCE_FETCH_SEEDS_EMPTY;
    } else {
        /* Eligible + attempted, but nothing installable landed. A persisted
         * <datadir>/bundles/directory.json means a manifest reached quorum but
         * the bytes did not complete; its absence means no reachable seed served
         * a usable manifest. */
        char hint[PATH_MAX];
        int hn = snprintf(hint, sizeof(hint), "%s/bundles/directory.json",
                          ctx->datadir);
        bool have_hint = hn > 0 && (size_t)hn < sizeof(hint) &&
                         access(hint, F_OK) == 0;
        out->fetch = have_hint ? NO_STATE_SOURCE_FETCH_DOWNLOAD_FAILED
                               : NO_STATE_SOURCE_FETCH_NO_SEED;
    }

    out->bundle = nss_failed_bundle_present(ctx->datadir)
                      ? NO_STATE_SOURCE_BUNDLE_FAILED
                      : NO_STATE_SOURCE_BUNDLE_NONE;
    out->baseline_hstar = reducer_frontier_provable_tip_cached();
}

/* ── The app_init selection seam ───────────────────────────────────────────── */

void boot_select_state_source(struct node_db *ndb, struct main_state *ms,
                              struct app_context *ctx,
                              struct boot_state_source_selection *out)
{
    memset(out, 0, sizeof(*out));
    if (!ctx)
        return;

    /* Capture the compiled checkpoint header's Equihash solution as IBD
     * headers fly past. Arming only after the height is already passed (the
     * repair condition's old path) misses the one header a new node needs.
     * Mainnet only: the compiled checkpoint is mainnet. Skip a datadir that
     * already holds sovereign installed state. */
    if (!ctx->regtest && !ctx->testnet &&
        !boot_consensus_bundle_marker_exists(ctx->datadir))
        checkpoint_header_fetch_arm_compiled();

    /* THE WELD (instant-on linchpin): on a fresh, marker-less datadir with no
     * local *.sqlite bundle, swarm-download the content-verified checkpoint
     * bundle into <datadir>/bundles/ so the autodetect below installs it under
     * the EXISTING fail-closed CHECKPOINT_ROM guards. Default-on for a fresh
     * datadir; opt out with -nofilesync or ZCL_NO_BUNDLE_FETCH=1. Best-effort +
     * fail-open: an absent manifest hint, no reachable seeder, or a failed /
     * byte-mismatched download lands nothing and leaves boot on its unchanged
     * path (P2P IBD / the operator bundle remain the fallback). Downloads bytes
     * only — it NEVER installs; the autodetect + CHECKPOINT_ROM authority is the
     * sole sovereignty gate and is not weakened here. */
    (void)boot_bundle_fetch_maybe(ctx->datadir, ctx);

    /* Import the swarm-downloaded header-chain seed (block_index.bin) into the
     * header index IN-PROCESS so pindex_best_header climbs to the artifact tip
     * THIS boot — the checkpoint-bundle install below defers on the header chain
     * reaching the checkpoint, and this replaces the serial ~4.7 GB P2P header
     * crawl that otherwise gates it. Verified flat load + header-only clamp; a
     * miss is fail-open (headers still arrive via P2P). No-op unless a fresh
     * node actually downloaded the artifact above. */
    (void)boot_header_seed_import_maybe(ctx->datadir, ms);

    /* 1b/1c — a complete-state install (durable request OR autodetected bundle)
     * SUPERSEDES the transparent-only from-anchor reset (which leaves shielded
     * state empty → the anchor_backfill_gap wedge). */
    out->auto_installed_bundle =
        boot_maybe_auto_install_consensus_bundle(ndb, ms, ctx->datadir);

    /* A1 — consume the sticky escalator's armed refold (bumps its bounded,
     * fsync-durable attempt budget) unless a complete install already fired. */
    if (!out->auto_installed_bundle && !ctx->refold_from_anchor &&
        boot_auto_refold_pending(ctx->datadir))
        out->consumed_auto_refold = boot_auto_refold_consume(ctx->datadir);

    out->do_from_anchor =
        !out->auto_installed_bundle &&
        (ctx->refold_from_anchor || out->consumed_auto_refold ||
         (ctx->load_verify_boot &&
          boot_load_verify_snapshot_eligible(ndb, progress_store_db())));

    /* LOUD no-state-source signage (conditions/no_state_source.h): if this boot
     * selected NO fast-start state source (no complete install, no consumed
     * refold, no from-anchor cutover), there is no staged/pending bundle and no
     * sovereign marker, AND the datadir has no meaningful chain state, NAME the
     * real problem NOW so a run that would otherwise pin folding an empty genesis
     * datadir surfaces the cause in the first seconds via `dumpstate blocker`,
     * instead of a misleading downstream fold symptom. The node still proceeds
     * with normal from-genesis IBD; the blocker self-clears on H* climb / a
     * source landing (the no_state_source condition's witness). */
    if (!out->auto_installed_bundle && !out->consumed_auto_refold &&
        !out->do_from_anchor &&
        !boot_consensus_bundle_marker_exists(ctx->datadir) &&
        !boot_install_bundle_pending(ctx->datadir) &&
        !nss_bundle_staged(ctx->datadir) &&
        nss_no_meaningful_chain_state(ms)) {
        struct no_state_source_facts f;
        nss_classify(ctx, &f);
        no_state_source_raise(&f);
    }
}
