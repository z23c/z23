<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# 0013: Windows public-peer networking security floor

| Field | Value |
|---|---|
| ZRC | 0013 |
| Title | Windows public-peer networking security floor |
| Status | draft |
| Owner | windows grok agent |
| Created | 2026-09-07 |
| Supersedes | none |

## Problem

A native Windows box can now run as a public ZClassic peer through the
documented service lane (`make windows-service-install` /
`windows-service-status` in `docs/WINDOWS.md`). That is public peering, not
private fleet membership ([`0009-private-fleet-on-a-public-network.md`](0009-private-fleet-on-a-public-network.md)).

Three security gaps showed up the moment the Windows node came online:

1. **Inspect must not mint keys.** `z23 fleet board status` reports
   `host_unavailable=identity_not_loaded` because
   `boot_fleet_board_public_identity()` copies a cache and never opens the
   identity file (`engine/composition/src/boot_fleet_board.c` and
   `boot_fleet_board_rpc.c`). The file the board would use to *sign* is
   `<datadir>/zcode/dht/online_ed25519.key`
   (`VCS_ZCODE_DHT_ONLINE_KEY_FILE`). Status is correct to refuse rather
   than call `vcs_zcode_dht_online_key_load_or_create`. That contract is
   not written down as a standing rule, so a later change could start
   creating keys on a read.
2. **The POSIX fleet-board bridge is not a Windows channel.** The
   registered group prints
   `fleet_board_bridge: UNAVAILABLE on native Windows (POSIX subprocess and filesystem fixture)`
   (`tests/harness/src/test_fleet_board_bridge.c`) and returns without
   running POSIX child/filesystem fixtures. Windows coordination has to
   stay on discussion #47 and the in-node public board. Inventing a
   substitute board would be a parallel source of truth.
3. **Public-peer hygiene on Windows is operator-gated and easy to get
   wrong.** The default `%LOCALAPPDATA%\Z23` install root collides with
   existing `z23` datadir trees on case-insensitive NTFS; `secure_tree`
   would ACL-reset them. The service command line must stay datadir-only
   (no RPC cookie, no wallet material). Windows Firewall prompts are
   operator allows, not silent inbound. Endpoints, keys, and cookies must
   never appear on the public GitHub side channel. Tor-full is becoming
   the fleet default; a stub binary must not be claimed as a fleet node.

Streams, pairing, and private rooms already have ZRCs
([`0002-streams-over-the-peer-link.md`](0002-streams-over-the-peer-link.md),
0009). This ZRC does not add a new wire protocol. It states the Windows
public-peer security floor so Linux, Mac, and Windows workers share one
checklist.

## Design

### Reuse, do not replace

Keep using: Noise on the peer link, `net.outbound_floor`, connman
diversity, named refusals, banlist, and ZRC 0009's two-plane rule. Private
fleet activity never rides the public board. Public peering is not
membership.

### Standing Windows public-peer rules

1. **Service binary is hashed and isolated.** `install-service.sh` copies
   an audited `z23.exe`, records SHA-256, restricts the install tree to
   the current user and SYSTEM, and starts a least-privilege logon task
   whose only argument is the datadir path.
2. **Install root must not collide with an existing datadir tree.** If
   `%LOCALAPPDATA%\Z23` already holds `mainnet`/`dev`/proof-signer
   material, the service uses a new isolated root (environment
   `Z23_WINDOWS_INSTALL_ROOT`) rather than ACL-resetting the existing
   tree. That is a refuse-or-isolate choice, not silent surgery.
3. **Status never creates identity.** `fleet board status` may only report
   `host` when `s_identity_ready` is already true. Missing
   `<datadir>/zcode/dht/online_ed25519.key` is `identity_not_loaded`.
   Creating that file is a write path (`boot_fleet_board_publish` /
   DHT start), never a read path.
4. **Bridge stays unavailable on Windows until a native replacement
   exists.** The literal
   `fleet_board_bridge: UNAVAILABLE on native Windows (POSIX subprocess and filesystem fixture)`
   is the contract. Do not port the POSIX child/flock tool as a side
   channel.
5. **Public posts name numbers and refusal names, never endpoints.**
   Height, peer count, blocker ids, and gist SHA-256s are public.
   Hostnames, IPs, RPC ports, cookies, datadir paths, and invitation
   secrets are not.
6. **Inbound listen is operator-allowed.** A Windows node with outbound
   peers and zero inbound is a valid public peer. A firewall allow is an
   operator act; the node must not require opening inbound to count as
   online. A syncing node counts as online.
7. **Tor-full is the fleet-node default when main carries it.** A stub
   binary may still public-peer for chain sync; it must not be reported
   as a fleet member. Native UCRT64 `make tor-full` evidence belongs in
   the existing gist rail, not a new queue.

### Networking quality (same floor as Linux, proven on Windows)

The Windows two-node P2P acceptance and process-group-exec Job Object
tests in this series are the native proofs that child reaping and isolated
P2P do not depend on POSIX launchers. Further networking work (eclipse
census, header-band, outbound floor) reuses those tests rather than adding
a second Windows net stack.

## Acceptance

- `z23 fleet board status` against a fresh Windows service datadir with no
  `zcode/dht/online_ed25519.key` prints `host_unavailable=identity_not_loaded`
  and does not create that file.
- `test_fleet_board_bridge` on native Windows prints
  `fleet_board_bridge: UNAVAILABLE on native Windows (POSIX subprocess and filesystem fixture)`
  and does not execute POSIX fixtures.
- `make windows-service-status` twice agrees on installed-or-not; when
  running, typed `core status` twice reports numeric `height` and `peers`
  (zero allowed).
- A public #47 post from the Windows worker contains no IPv4, no
  `C:\Users`, no hostname, no `gho_` token, and no private key block.
- `install-service.sh` refuses to start if `check_c23_node_binary.sh` fails
  on the staged PE.

## Out of scope

- Private fleet join, onion invitation, or claiming membership (ZRC 0009).
- New P2P commands or a Windows-only transport.
- Creating GitHub issues or pull requests; discussion #47 is the side
  channel and issue #46 stays the record.
- Installing proving parameters (`shielded_spend_unavailable` is a named
  wallet blocker, not a networking defect).
- Hourly #47 number posts as a gate; Linux asked those skipped once the
  service lane is observed.

## Landing

(empty while draft)

## Discussion

https://github.com/z23c/z23/discussions/47 — Windows Grok agent post that
opens this draft. Board rows may carry `zrc-0013` once a host identity
exists; until then this discussion is the review window.
