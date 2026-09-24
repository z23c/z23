<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# SkyCombat aircraft: second independent verifier

Date: 2026-09-24. The frozen input bundle came from source commit
`255990bfdc48e0c7e6f966aa2e8d6e678b25ca40`. Its 24-file input manifest
has SHA-256 `1abf6aa907a1d2c74ca516f59a9a84a71501fbd50549b5db135d11334b5fdd0d`;
the 117,504,000-byte transfer bundle has SHA-256
`2909b4f13b502cd34fd8acccab21a8042fbe100138a4ad246f2f14b9119ee2d1`.
The package source root is
`9a2c62d39213dd36a2e05ca064ac011d100ff429f92eecedd2f2682307495acc`.
The allowlisted libm control recipe is separate from SkyCombat's canonical
recipe, which refuses as `BUILD_NOT_INSTALLABLE`.

Two consenting Linux development peers each received the same bundle, checked
all 24 input files, and ran the frozen confined verifier. The second peer used
GCC 14.2.0 on an AMD Ryzen 9 7950X3D; the first peer reported the same
compiler and CPU model. The verifier accepted the good aircraft package with
`isolation=full`, scoped filesystem, denied network and enforced limits. It
refused a compile-valid wrong-boost source under the standard profile. The
second peer's good and wrong verifier calls took 5.006 s and 2.471 s,
respectively; these are verifier wall times, not transfer or acceptance latency.

| Evidence | SHA-256 |
| --- | --- |
| Second peer returned evidence tar | `b39a2ac0d72f113577c7525bba7e68cb086040580ad40cf889227b7ac59fb379` |
| Second peer good build report | `e212bc6060500af3487034533db06444f0ce5909549667d54e158f6367da0f05` |
| Second peer good static library | `8c1017874fcb6f7e1b8fc11496d0357955cbc8a75a0fac354296a428843195ed` |
| Second peer input-check log | `f0e4dc875149f25cb83e6eb031b9f3ddfe57efed3338459606027f063610201b` |
| Second peer node-health samples | `036c4a1697634ee5882c238633aff4e7889eb0d817478abb7bdb4b7ebd50616a` |

The first peer's good build report and static library have the **same exact
SHA-256 values** as the second peer's outputs. Both peers returned verifier
exit 0 for the good source and exit 6 for the wrong source. The second peer's
returned `outputs.sha256` verified all five listed files locally after
transfer. The wrong source's local flight test printed a boost of 60 instead
of the required 110; the standard confined verifier refused its test runs.
This is an executable behavioral counterexample, not an inferred code review
verdict.

The local machine ran bounded commands on both peers. Each peer then reached
the other directly with its existing SSH user key and an ED25519 host key
pinned from the local known-hosts file. Each direction transferred a distinct
object through the direct SSH session and matched sender and receiver SHA-256:
`c80e3f7969a35253c4552e5426229ed7e028662b5ed9bca64154e3372c318704`
in one direction and
`9287b4964c2aa35bffb221093ec927792bfa93f5b727868096981cca61ae64c1`
in the other. Peer DNS names did not resolve on the opposite hosts, so the
test used locally resolved addresses with the pinned host identities. It did
not require a relay for peer-to-peer SSH. Private endpoints and credentials
remain outside this record.

To repeat the verifier on a consenting, compatible Linux host after transferring
the exact bundle and checking its transfer SHA-256:

```bash
mkdir -m 700 skycombat-peer-check
cd skycombat-peer-check
tar -xf ../bundle.tar
sha256sum -c inputs.sha256
bash run.sh
sha256sum good-emit/build-report good-emit/lib/libskycombat-aircraft.a
cat good.exit wrong.exit good.time wrong.time
```

The second peer's resident-node status command succeeded in all ten samples.
The before-load response was `STATUS_SOURCE_UNAVAILABLE`; eight during-load
samples and the after-load sample reported `review_required_bootstrap_trust`.
The node was blocked before useful synchronization could be measured. These
samples do not establish that package work leaves chain advancement healthy
under load. They also do not attribute the transient initial status to the
verifier. No package was published, installed into an operator application,
DEV-accepted, or fully accepted by the SkyCombat owner.
