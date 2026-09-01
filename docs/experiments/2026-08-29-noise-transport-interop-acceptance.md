# Noise transport two-node interop acceptance

Date: 2026-08-29

## Intent

Produce the live evidence artifact for the owner's `-noisetransport`
default-flip decision. The census (`dumpstate connman` → `noisetransport`)
counts who advertises; this acceptance proves what a noise-enabled node
actually DOES with plaintext and noise peers on real isolated regtest
daemons, asserted only on operator-visible surfaces
(`dumpstate transport` per-peer mode/state/frame counters plus the census),
never on log scraping.

## Harness

`make test-noise-transport-interop` → `tools/dev/noise_transport_interop.sh`
(opt-in, not in `make ci`; process ownership via
`tools/dev/node_lifecycle.sh`; P2P listeners that the capability-learning
reconnect must redial use reachable-policy ports 9033/18033/20028 per
`core/modules/net/include/net/port_policy.h`).

Four scenarios:

- **S1 noise→plaintext outbound.** A(`-noisetransport=1`) dials B
  (plaintext). B's address carries no `NODE_NOISE_TRANSPORT` bit, so A never
  arms the transport — the exact legacy path.
- **S2 plaintext→noise inbound.** B (plaintext) dials A (noise listener).
  A's `NOISE_DETECT` sees plaintext network magic, takes
  `NOISE_PLAINTEXT_FALLBACK`, frees the transport, replays buffered bytes.
- **S3 noise↔noise.** N1 dials N2. First contact is plaintext (a manual
  `-connect` address has no service bits); N2's version advertises the bit,
  `connman_request_noise_upgrade` persists it on the addnode dial entry and
  drives one controlled reconnect that arms Noise XX as initiator.
- **S4 mixed swarm.** P (plaintext) + N1 + N2 fully interconnected — the
  mid-rollout live-network shape — with tip consensus before and after
  fresh mining.

## Result

PASS on the first full run (2026-08-29, GCC/zcc build, Linux x86_64).
Asserted values, verbatim from the run:

- S1: tip propagated A←B over plaintext (height 10); A `noise_enabled=true`,
  `noise_peers=0`, `plaintext_peers=1`, `peers[0].mode=plaintext`; A census
  `advertising_now=0`, `default_enabled=true`; B `noise_enabled=false`,
  `plaintext_peers=1`; **B's census sees A's advertisement**
  (`advertising_now=1`) — legacy nodes observe the rollout.
- S2: tip propagated B←A over the fallback (height 10); A
  `plaintext_peers=1` with `peers[0].mode=plaintext`, `noise_peers=0`;
  census `advertising_now=0`.
- S3: N1 `noise_peers=1`, noise peer `state=established`,
  `is_initiator=true`, `send_frames=6`, `recv_frames=6`; N2 mirror image
  (`is_initiator=false`, `send_frames=6`, `recv_frames=6`). Application
  traffic flowed sealed in both directions.
- S4: P `plaintext_peers=2`, `noise_enabled=false`, census
  `advertising_now=2` with `default_enabled=false` (a default-off node
  mid-rollout sees both noise peers and stays plaintext); N1 census
  `advertising_now=1`; tip consensus at 10, then at 15 after mining 5 more
  over the mixed fabric; the N1↔N2 session stayed `established` through
  block relay.
- Cleanup proof: `owned_processes_remaining=0 ports_rebindable=true`.

## Evidence

```text
make test-noise-transport-interop
```

prints one `OK:` line per assertion with the actual value and ends with
`noise-transport-interop: PASS: ...`. A failure prints `FAIL:` lines naming
the expected and observed values and exits 1.

## Consequence for the default-flip decision

Interop risk is now measured, not argued: a noise-enabled node is
indistinguishable from a legacy node toward plaintext peers in both
directions, and upgrades to authenticated encryption exactly when both
sides advertise. The remaining precondition for flipping the default stays
what `core/modules/net/include/net/connman.h` states: a measured population of
advertising peers on the live network (the census high-water), which is an
owner decision, not a code property.
