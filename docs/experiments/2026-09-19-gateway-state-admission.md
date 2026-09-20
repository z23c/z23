<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Gateway state admission, 2026-09-19

The loopback gateway's OAuth approval nonce must be single-use across
connection children. The nonce check and append now hold one exclusive file
lock. A malformed or unreadable rate-window record refuses admission instead
of resetting the count. Registration returns a server error if its client-row
write or close fails.

The registered `fleet_gateway` group passed from this checkout after rebuilding
both `z23` and `fleet-gateway`: 1/1 group, 0 skips, 12.4 s test-body time.
The group covers sequential nonce replay and a malformed registration-rate
record; it does not yet exercise concurrent approval POSTs or injected write
failure. Those require isolated fault/concurrency fixtures before the stronger
claims can be made.
