<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Android stopping guidance

When a node remains alive after accepting Stop, Home keeps its stopping state
and explains that other screens remain usable. The app does not send another
signal or offer Start while the process remains alive. This guidance does not
resolve a hung shutdown.

A synthetic simulator fixture showed the prior stopping state and confirmed
Apps and Home remained navigable without starting or signaling a real node.
The focused Home fixture passed the revised text and existing fixed-height
checks. At 1080x2160, density 540 and font scale 1.5, a synthetic stopping fixture showed both title lines and Apps navigation in both Home layouts; default-layout control bounds matched the baseline. Classic baseline bounds were not captured. The fixture did not start or signal a node. Report SHA-256: `c852a7e52da8c25ed76c06a0289dbffa4b72f844536ced5f0b9ca4080957d7e3`.

On 2026-11-08, Stop during an existing wallet’s block-index projection replay
reached the node, but replay continued until the 90-second shutdown watchdog
forced exit. The committed projection cursor and wallet fingerprint survived.

Projection replay now accepts a typed Stop between validated records, commits
its completed prefix, and propagates failures ahead of Stop. Focused host
checks passed all eight projection shards and their umbrella group (9/9, zero
skips), as well as the populated-wallet startup cleanup fixture. They cover
committed-prefix recovery and injected SQL errors. Android Stop latency and
reopening the existing wallet with this change remain to be measured.

A later Pixel run stopped projection promptly but left the early Tor worker
running during offline shutdown; the drain timed out and exited uncleanly.
The projection cursor advanced durably and the wallet fingerprint remained
unchanged. Offline shutdown now requests early Tor and onion-service shutdown
before joining registered workers, retaining its deadline and durability checks.

Focused host tests passed the snapshot recovery and Tor groups (2/2, zero
skips). Both real linked-Tor projection Stop and error cases ran with network
disabled and verified wallet preservation. Android Stop latency and clean exit
with this change remain to be measured.
