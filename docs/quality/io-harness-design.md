# Network-IO Adversarial Simulation Harness (simnet_wire) — Design

The harness simulates the node's real network IO in-process so it can model
and monitor any adversarial network without sockets or wall-clock time.

## Core insight
The NUT's code above recv()/send() is already isolated behind two calls:
- INGRESS seam: `p2p_node_receive_bytes(node,data,nbytes,msgstart)` — core/modules/net/src/net.c:428.
  Real recv() at connman.c:1223 feeds it at 1225. Substitute here: feed bytes from memory.
  Framing/partial-reads native (net.c:437-497). Recv queue+OOM cap MAX_RECV_MESSAGES
  (net.c:438-458,482). Checksum+dispatch+handshake gate msg_process_messages (msgprocessor.c:1603,
  1630-1648,1686-1693). Backpressure connman_recv_cap_for_queue (connman.c:62,1206). Bandwidth
  peer_bandwidth (connman.c:1195). Ban scoring node->misbehavior (net.c, ban at 100) +
  peer_scoring_should_ban (peer_scoring.h) + is_banned/ban_until (net.h:416,138).
- EGRESS capture seam: the send_segment list node->send_head (built by p2p_node_end_message
  net.c:636-691). Drain it directly (like fuzz_p2p.c:205-214), NOT socket_send_data (net.c:702)
  whose send() would EBADF since socket==ZCL_INVALID_SOCKET. Captures byte-exact framed+checksummed
  wire image without a socket.
- THREADS: spawn NEITHER thread_socket_handler (connman.c:1113) NOR thread_message_handler
  (connman.c:1657). One deterministic single-threaded pump.

## Module: simnet_wire (engine/modules/sim/src/simnet_wire.{c,h})
In-memory transport carrying REAL wire frames between a real struct p2p_node (NUT) and N peers,
scheduled by seed_tape, cloning simnet_cluster's delivery queue.
- wire_link: byte_ring to_nut/to_peer, open flag, bw tokens.
- wire_event: {peer_id, deliver_us, seq, bytes, kind: DELIVER_TO_NUT|OPEN|CLOSE|PARTITION}.
- Scheduler clones simnet_cluster_enqueue/deliver_one (simnet_cluster.c:94-223): latency/reorder
  via rng (formula c:104-108), virtual clock via seed_tape_advance (c:205-212), ordered pop
  find_next_ready+delivery_less (c:132-180), FNV determinism fingerprint (c:59-73).
- Pump per tick: pop ready events; for DELIVER_TO_NUT split into transport-chosen chunks (partial
  reads), APPLY THE SAME RECV GATES the socket thread applies (queued>=MAX_RECV_MESSAGES defer per
  connman.c:1206; recv_cap=connman_recv_cap_for_queue then bw-cap per c:1216-1218; call
  p2p_node_receive_bytes; on false set node->disconnect per c:1225-1230); call msg_process_messages
  (bounded ZCL_MSG_PROCESS_MAX_PER_CYCLE); drain send_head to link.to_peer + monitors; PARTITION via
  net_partition_until_unix() (net_fault.c:9 — the EXISTING seam, honored in net.c:432 +
  msgprocessor.c:1657; reuse, don't reinvent).

## Adversarial peer model (simnet_wire_peer.c)
Seed-driven byte generator; catalogue modeled on simnet_byzantine g_meta[] (class->reason->expected
blocker_class). Kinds: HONEST, MALFORMED_FRAME (bad checksum/oversized nMessageSize/bad magic —
reuse fuzz_frame_payload fuzz_p2p.c:167-197, oversized asserted net.c:482), BAD_HANDSHAKE (data
before version / verack-first / garbage), FLOOD (inv/addr/getdata storm), SLOWLORIS (1 byte/many
ticks), INVALID_BLOCK/INVALID_HEADER (REUSE simnet_byzantine builders, serialize, frame — same
artifact now travels the wire), REPLAY, ECLIPSE, FUZZ (raw seed bytes + g_inbound_commands[]
fuzz_p2p.c:55-69). child_seed = splitmix64(master_seed ^ peer_id) off the installed seed_tape RNG
(only entropy source). Scenario = {master_seed,[(kind,count)],honest_count,duration_us}; replays
identically.

## Monitors (observe after each tick + at end; each maps to real observable)
- Never crashes: ASan/UBSan build (FUZZ_TARGETS flags, Makefile:1578).
- Never silently halts (PRIME): blocker_snapshot_all over registry (blocker.h BLOCKER_CAP=128); no
  unexpected BLOCKER_PERMANENT; expected cls from simnet_byzantine g_meta[].
- Ban/disconnect: node->misbehavior reaches threshold, node->disconnect set, is_banned true;
  INVALID_BLOCK (weight 100) banned after expected offences.
- Recv queue bounded: node->recv_msg_count <= MAX_RECV_MESSAGES always under FLOOD.
- Mem/CPU bounded: send_size/recv_msg_count/inventory_*/addr_to_send plateau (no monotonic growth).
- Consensus correct: tip hash + UTXO digest (simnet_cluster_tip_hash/coins_digest pattern
  c:337-352) unchanged by invalid input.
- Recovers: after net_partition_clear()/flood ends, tip advances from honest peer.
- Events: EV_PEER_MISBEHAVE/EV_MSG_CHECKSUM_FAIL/EV_BACKPRESSURE_REJECT (msgprocessor.c:1639,1658;
  net.c:444). On violation dump seed → capsule (seed_tape_save).

## Harness security (owner emphasized)
1. No socket syscalls: simnet_wire never includes <sys/socket.h>, never connman_start/thread_*/
   accept/dns_seed; NUT = p2p_node_create(nm, ZCL_INVALID_SOCKET,...) (fuzz_p2p.c:133); egress
   drained from send_head. CI grep-gate: engine/modules/sim/src/simnet_wire.c + tools/sim/*wire* contain no
   recv(/send(/socket(/connect(/bind(/getaddrinfo(.
2. No wall clock/entropy: seed_tape_install hooks platform_rng+clock; assert seed_tape_rng_count
   accounts for all randomness; clock only via seed_tape_advance.
3. Adversarial generators unreachable from prod: all under engine/modules/sim/+tools/sim/ (not linked into
   zclassicd, same as simnet_byzantine); no net/validation may #include "sim/".
4. Sandboxed to read-only fixtures; no /tmp writes except explicit capsule path.
5. Bounded runtime: max_ticks + stuck-guard (simnet_cluster.c:327-330).
6. Consensus untouched: links unmodified connect_block/msg_process_messages; only reads tip/digest.

## Efficiency
Zero syscalls/threads; per-msg ≈ one reassembly + dispatch (~tens of k msgs/sec like fuzz_p2p);
fixed peer/link pool (SIM_PEER_MAX 1024); batch pop-all-ready + single clock jump per tick.
CI tier: ~8-12 seeds (one per adversary kind), few hundred ms, group test_simnet_wire. Nightly:
tools/sim/wire_sweep.c, thousands of seeds under ASan/UBSan, save failing seeds as capsules
(excluded from ci: like soak/fuzz).

## Build order (top-3 first)
A. Transport engine + honest loopback (simnet_wire.{c,h}): NUT<->1 honest peer real version/verack
   + one valid msg, in memory, deterministic. group test_simnet_wire "handshake+echo". M.
B. Malformed/flood/slowloris peers + core monitors (simnet_wire_peer.c): checksum-fail events,
   recv-queue bounded, ban threshold, disconnect. M.
C. Byzantine-block wire injection (byzantine bridge): wrap simnet_byzantine artifacts into
   block/headers frames; tip/digest unchanged, expected typed blocker, peer banned. M.
D. eclipse/partition/recovery via net_fault. E. replay/reorder/bandwidth + fingerprint determinism.
F. wire_sweep.c nightly + capsule save + grep security-gate.

## Critical files
net.c (p2p_node_receive_bytes:428, socket_send_data:702, p2p_node_end_message:636, p2p_node_create:289);
connman.c (recv 1223-1230, connman_recv_cap_for_queue:62/1206, bandwidth 1195, threads 1113/1657);
msgprocessor.c (msg_process_messages:1603, checksum 1630-1648, handshake 1686); simnet_cluster.c
(scheduler pattern); fuzz_p2p.c (threadless ingress+frame-build+reset); simnet_byzantine.c
(artifacts+g_meta[]); seed_tape.h + net_fault.c (determinism + partition seam).
