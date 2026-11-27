<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Ironwood standalone testnet candidate

These public vectors describe an isolated test network starting at height zero. This fresh genesis contains no existing user balances. A migration preserving ZClassic notes needs an agreed source chain and transition. A deployable Ironwood profile, activation rules and peer discovery remain pending.

## Genesis

| Field | Candidate value |
| --- | --- |
| Block hash, display order | `0eadaa0b42b377b8d05d1a9b313f1795b8ac4553217a5d06b0f66cddff8c78e7` |
| Coinbase txid and Merkle root, display order | `5b311545eb0a91c0b813e94b62a1cff6b29fee9c948f0dc8bf3fee59747c860d` |
| SHA-256 of the serialized block | `d205e8a42fcad376d3610c2a7203bd94840c21189f6075701953d50b01e7b91c` |
| Header | Version 4, timestamp 1795737600, zero parent and final Sapling root |
| Research mining parameters | Equihash (48,5), compact target `0x200f0f0f`, little-endian nonce 1 |
| Coinbase | Version 1, message `Ironwood research testnet 2026-11-27`, one zero-value OP_RETURN output |

Concatenate and hex-decode the lines below to obtain the 276-byte block. The 177-byte header includes the Equihash solution. The next byte gives the transaction count. Double SHA-256 of the header gives the raw block hash. Reverse the digest for display. Hash the single transaction the same way to reproduce its txid. The header contains the Merkle root in raw digest order.

```text
0400000000000000000000000000000000000000000000000000000000000000
000000000d867c7459ee3fbfc80d8f949cee9fb2f6cfa1624be913b8c0910aeb
4515315b00000000000000000000000000000000000000000000000000000000
0000000000c8086b0f0f0f200100000000000000000000000000000000000000
0000000000000000000000002418165051b5ee3aa3bb33654e2a069bfadba042
a5675987b7634bba54c037fe261cbddfc2010100000001000000000000000000
0000000000000000000000000000000000000000000000ffffffff252449726f
6e776f6f6420726573656172636820746573746e657420323032362d31312d32
37ffffffff010000000000000000016a00000000
```

## Transport and storage

The proposed message-start bytes are `d4 14 83 fa`, in that order. Take the first four raw bytes of SHA3-256 of ASCII `Z23/Ironwood/testnet/transport/v1`, excluding the terminator. An example ping frame is `d41483fa70696e670000000000000000080000002502fa940102030405060708`. Its eight payload bytes have the four-byte double-SHA-256 checksum `2502fa94`.

A node profile needs an explicit startup selector, a separate base datadir and wallet address namespace, and discovery settings for this network. Boot opens wallet and chain stores under the base datadir. The profile must gate each use of compiled mainnet checkpoints and ROM artifacts on positive mainnet identification. Before public use, two fresh full nodes should sync from the candidate genesis, agree on block hashes, survive restart and reject foreign network frames through normal startup.

<!-- claim: symbol-present boot_step_select_chain_and_datadir engine/composition/src/boot.c # compiled startup network selection -->
<!-- claim: symbol-present get_sha3_utxo_checkpoint core/chainparams/src/checkpoints.c # compiled checkpoint provider -->

## Example ballot round

The [signaling catalog](MINER_SIGNALING.md) uses the raw genesis hash and a separate fork ID. For this example use SHA3-256 of ASCII `Z23/Ironwood/testnet/experimental-round/v1` without a terminator. The fork ID is `0470426015683b2d25ae8014a684975fa4841720b848c22457ee8f510a1ab718`. Hash the exact proposal file bytes at revision `223f48c5fb361f2a0024909fc75cb557bd1c7e37` with SHA3-256 for the two rule revisions below.

| Slot | Proposal | Rule revision | Example activation height |
| --- | --- | --- | ---: |
| 0 | [Block size](BLOCK_SIZE_UPGRADE.md) | `6768eafc3e43a946ac945bdec839f5cdc751e6be73570b53b6101b65616fa286` | 23 |
| 1 | [Sapling deposits](SAPLING_DEPOSIT_UPGRADE.md) | `dd9a28179af68e0e8b65831cca98d73c398da03ae66cc0e50f0f810904a664e8` | 24 |

Voting at heights 1 through 20 yields the v1 catalog digest `a2eebcca533c2173cea136af4085fe50d7523b5e0d70b2d895ba0b106f70ff73`. Signal both slots at heights 1–18, only slot 0 at 19, and abstain at 20. On this branch the expected tally is 19 and 18. Slot 0 locks in for blocks 21 and 22 and first reports active for block 23. Slot 1 expires. These heights are test inputs. Adopting the block cap, preserving protected rewards and withdrawals during a deposit freeze, and selecting any new proof of work each require separate decisions.
