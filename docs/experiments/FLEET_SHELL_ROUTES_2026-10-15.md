<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Four-host shell and transfer observation — 2026-10-15

rhett3.dev and rhett4.dev were retired on 2026-10-18; this record is historical evidence.

All twelve directed pairs among z23-r1, z23-r2, z23-r3 and z23-r4
completed both a direct SSH exchange and an SSH-forwarded exchange.
Each source initiated its own three peer connections; the coordinator did not
stand in for a missing peer route. Existing account keys and host pins were used.

Each exchange sent a source/target-specific text file, executed hostname and
sha256sum on the receiving host, and deliberately exited 23. Source and
receiver hashes matched and the SSH client propagated exit 23 in all 24
exchanges. The temporary receiving file was removed after hashing. Retained
source payloads, stdout and SSH diagnostics remain available below.

Every direct connection negotiated sntrup761x25519-sha512@openssh.com.
The forwarded exchanges used an outer SSH stdio-forwarding connection to
the peer's loopback SSH listener, followed by an authenticated inner SSH shell.
Both layers negotiated the same hybrid KEX. Public-key authentication and
strict existing host-key checks succeeded. Authentication was not upgraded
to post-quantum signatures by choosing a hybrid key exchange.

| Source / destination | r1 | r2 | r3 | r4 |
| --- | --- | --- | --- | --- |
| r1 | — | PASS | PASS | PASS |
| r2 | PASS | — | PASS | PASS |
| r3 | PASS | PASS | — | PASS |
| r4 | PASS | PASS | PASS | — |

## Retained evidence

Each directory is relative to the named host's home. It contains one payload,
direct stdout/stderr, forwarded stdout/stderr and carrier stderr per peer.
VERIFIED.txt records the checksum, exit-status and carrier-KEX comparisons.
SHA256SUMS binds those files; its own SHA256 is listed here.

| Host | Directory under .local/state/z23 | SHA256 of SHA256SUMS |
| --- | --- | --- |
| r1 | fleet-route-demo.1nrid4 | ec56fd157c7238790f839cb02512c8fdae951854cb890295eb80876037ae3d8d |
| r2 | fleet-route-demo.ouGrDh | 75420c765eadb794830fded5944447340255da773e2fef0c3d583657c3198e70 |
| r3 | fleet-route-demo.nqygug | ca3f0bbcf66d98e9cf45fc73d7fd506380dfc4e63b6663494e54b502e2d67d3b |
| r4 | fleet-route-demo.gzukqD | 556e4ff558a1e583276260b659e48607f115b4f5c2eea26e5e11eac9a5a7f98a |

r1/r2/r3 reported OpenSSH 9.6p1 Ubuntu-3ubuntu13.20; r4 reported
OpenSSH 9.6p1 Ubuntu-3ubuntu13.19. These are observed installed versions.

## Scope

This observation qualifies bounded shell execution and exact-byte transfer
through existing OpenSSH routes. It is not native Z23 HOST acceptance, a
benchmark, a persistent service installation, or proof that
four agent sessions are currently active. No keys were forwarded, host pins
changed, service restarted or firewall modified. No Z23 receiver was started.

The command recipe remains in the single
[fleet guide](../agent/FLEET.md#shells-and-remote-commands).
Builds still require devbuild admission and source changes still require
component ownership. Route availability grants neither consensus nor custody
authority.

## Mac peer extension

A subsequent run on the same date added z23-mac in both directions with
each Linux host: eight directed pairs, each exercised directly and through
the forwarding carrier. All sixteen additional exchanges matched payload
SHA256 and exit 23. Both SSH layers negotiated
sntrup761x25519-sha512@openssh.com. The Mac reported OpenSSH 10.0p2.
Together the two runs cover every directed pair among five physical hosts;
they do not establish agent session presence or native HOST support on Mac.

The same evidence layout is retained under .local/state/z23 in each host's
home:

| Host | Directory | SHA256 of SHA256SUMS |
| --- | --- | --- |
| Mac | fleet-mac-route-demo.zdk1ml | 69856ba76b1b390f77b9b9543f1f1316cfe79ad6aaecc700e691992a46e6aef9 |
| r1 | fleet-mac-route-demo.3GsK0L | 0a8914f8c8f06a36f8e22bf3ac43ccf523b2e82c2ac435e85a363104c8fcce27 |
| r2 | fleet-mac-route-demo.yRdDAs | 29aca55dfdd22175df9cad2bb574becd32e0bb870bdab7642829572dc74fb2e8 |
| r3 | fleet-mac-route-demo.JN4dkJ | dd5f2ec3b73b26a73909ef22db0947cdfea15df74d8ef4a7bade4ff379c63960 |
| r4 | fleet-mac-route-demo.iPIoD1 | d4a3632d523c8f6220caaa36fb4e422f873d1c41726b967c2f0c408bd9f6dea6 |

The existing z23-mac alias supplies its account, gateway port and host pin;
do not replace these with the Linux account or a guessed external port.
The forwarding destination remains the peer's loopback SSH listener.
