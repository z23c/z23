# MVP live-node gate — `tools/mvp_gate.sh`

A **read-only** probe of the *running* node that scores the 8 MVP
acceptance criteria (`docs/MVP.md`) against what the live node actually
demonstrates right now, plus a **soak-accrual** check (continuous-uptime
+ at-tip duration toward the 168h C6 window).

This is the **live** companion to `tools/scripts/mvp_scoreboard.sh` (which
runs the *hermetic* test slices behind `make mvp`). The two are
deliberately split:

| reporter | proves | resource needed |
|----------|--------|-----------------|
| `mvp_scoreboard.sh` (`make mvp`) | the mechanical/hermetic slices ran + passed | none (CI-safe) |
| `mvp_gate.sh` (this) | what the *live running node* demonstrates now | a running node |

Both compute MRS the same way (`docs/MVP.md` rule): **MRS = count of
criteria PASS at the FULL operator-claim level.** A hermetic slice that
passes, or a live surface that answers but whose full claim needs the
sovereign foundation, is `BLOCKED(reason)` and does **not** count. Live
observations alone do not establish full acceptance.

## Run

```bash
tools/mvp_gate.sh            # human report + MRS + soak accrual
tools/mvp_gate.sh --json     # one machine-readable JSON object
tools/mvp_gate.sh --strict   # exit 1 if a live criterion that SHOULD pass FAILs
```

Default exit is always 0 (status reporter — `BLOCKED` is the honest,
expected state of several criteria). `--strict` exits 1 on a real live
regression (a judged cold-start failure => C3 FAIL, height divergence vs zclassicd =>
C8 FAIL, shielded-receive surface down => C4 FAIL, node unreachable).

### Env overrides
- `ZCL_RPC_BIN` — c23 client (default `build/bin/zcl-rpc`)
- `ZCL_NODE_UNIT` — systemd `--user` unit whose `ExecStart` supplies the
  live `-datadir` / `-rpcport` defaults (default: `ZCL_SOAK_UNIT`)
- `ZCL_DATADIR` / `ZCL_RPCPORT` — explicit live-node RPC target overrides;
  when unset, the script reads them from `ZCL_NODE_UNIT` and falls back to
  `~/.zclassic-c23` / `18232`
- `ZCL_SOAK_UNIT` — systemd `--user` unit for uptime (default `zclassic23`)
- `ZD_RPCPORT` — zclassicd oracle RPC port for the parity probe (default `8232`)
- `ZD_DATADIR` — zclassicd datadir for oracle auth (default `~/.zclassic`)
- `TIP_GAP_OK` — max blocks-behind-peer still "at tip" (default `10` = `ZCL_FINALITY_DEPTH`)

## What each criterion probes live

- **C1** — `getblockchaininfo` answers ⇒ availability observed, **BLOCKED**
  for full acceptance. The probe has no current receipt binding install and
  portability qualification to the running executable. `make ci-symbol-floor`
  supplies supporting build evidence; naming that target proves no run.
- **C2** — `z23 core network onion status` reports onion readiness and an
  address. Healthy readiness remains **BLOCKED** until a measured bootstrap
  under 60 seconds is bound to the running executable. The supporting
  `make mvp-onion-local` target alone is not that qualification.
- **C3** — judge the wipe-to-tip stopwatch ledger against the running
  executable's artifact hash and freshness limit. A qualifying PASS earns
  credit; a judged failure is FAIL; unavailable or unqualified evidence is
  BLOCKED. Current tip proximity alone cannot prove a cold start.
- **C4** — sapling z-addr present + `z_gettotalbalance` answers ⇒ receive
  surface observed, **BLOCKED** for full payment acceptance. The supporting
  `make test-shielded-payment` isolated proof is not consumed here as a
  full receipt bound to the running executable. If
  `z_gettotalbalance` answers but no z-addr is listed, the live probe reports
  BLOCKED rather than creating one, because `z_getnewaddress` mutates the wallet.
- **C5** — catalog and `app.store.remotebuy` availability are supporting
  observations, **BLOCKED** until exact full remote-buyer qualification.
  The full journey is exercised by `tools/dev/store_onion_acceptance.sh`;
  historical runs do not qualify the current executable.
- **C6** — BLOCKED to the soak window; the **soak-accrual** line reports
  how far the current continuous uptime has gotten (see below).
- **C7** — BLOCKED (live kill forbidden by guardrails); surfaces the
  supporting signal that the systemd or launchd service is supervised for
  failure recovery and active
  (auto-recovery armed). Full proof: `make test-crash-bootstrap` +
  `make test-two-node-peer-tip`.
- **C8** — require a fresh genesis replay PASS bound to the running source
  and artifact, plus coarse height agreement with the zclassicd oracle.
  Fresh canary failures or live height divergence report FAIL; missing,
  stale or mismatched qualification and an unavailable oracle report BLOCKED.

## Soak-accrual check (toward C6)

Read-only from the systemd or launchd process start time, a trustworthy
restart counter when the service manager exposes one, and the live at-tip
flag:

```
soak-accrual: VERDICT=<v> uptime_s=<n> pct=<n> restarts=<n|null> at_tip=<0|1> reason="..."
```

- `NOT_MET` — `NRestarts>0` (intervention/crash broke the window) **or**
  node not at tip (soak time does not accrue while behind tip).
- `ACCRUING` — continuous uptime at tip, 0 restarts, `< 168h`. `pct` is the
  fraction of the 168h window covered.
- `WINDOW_LONG_ENOUGH` — `>= 168h` continuous at tip, 0 restarts makes the
  observation eligible for authoritative judgment by `make soak-evidence-report`.
  Uptime alone does not establish MET.
- `INSUFFICIENT` — no uptime read, or no trustworthy restart counter. launchd's
  `runs` value is deliberately not treated as a restart count because it also
  includes initial and manual launches.

This is an *instantaneous* accrual signal; the authoritative 168h verdict
is the JSONL judge in `tools/scripts/soak_evidence.sh`
(`make soak-evidence-report`). This script does **not** replace it — it
tells you at a glance whether the current uptime window is even eligible
to accrue.

## `make mvp-live` target (suggested — not yet wired)

Add alongside the existing `mvp` target (do not modify `ci`):

```make
.PHONY: mvp-live
mvp-live: ## live-node MVP probe + soak accrual (READ-ONLY, status only)
	@tools/mvp_gate.sh
```

Keep it **out of `make ci`** (CI has no running node and must stay
hermetic/local-only). It is an operator/dispatch convenience: a one-shot
`make mvp-live` to see the live MRS + soak accrual. If ever wired to fail a
gate, use `tools/mvp_gate.sh --strict` so only a genuine live regression
(C3/C4/C8 FAIL) is non-zero — never a `BLOCKED`.

## Live numbers

Run `tools/mvp_gate.sh` for the current MRS, gap, and soak-accrual state —
do not trust a pinned snapshot in this file; heights, gaps, and MRS rot
every session. `docs/HANDOFF.md` §0-LATEST carries the current live-node
narrative; this file only documents the script's contract.
