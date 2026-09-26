<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# ZCL Sign Test for Ledger Blue

This C23 app tests a real seed-derived transparent ZCL key on a dedicated
Ledger Blue. The derivation path is fixed at `m/44'/147'/0'/0/0`. After the
owner taps `SIGN TEST`, one USB command signs the SHA-256 digest of the fixed
text `Z23 ZCL Blue signing self-test v1`. The reply contains a compressed
secp256k1 public key and a DER ECDSA signature. The host verifies the
signature and encodes the public key as a ZCL transparent address.

The app accepts no host-supplied message, digest, path, or transaction. The
one-time touchscreen tap authorizes only this fixed test. `EXIT` returns to
the Blue home screen. No ZCL transaction, Sapling spend, or payment can be
signed by this app. Do not use the resulting address for funds.

Build with the reviewed Blue SDK and an ISO C23 compiler:

```sh
make -C apps/zcl-ledger/device-blue-sign-test \
  BOLOS_SDK=/path/to/blue-sdk \
  ARM_INCLUDE_DIR=/path/to/arm-none-eabi/include \
  GCCPATH=/path/to/toolchain/bin/ \
  CLANGPATH=/path/to/clang/bin/
arm-none-eabi-objcopy -O binary --only-section=.text \
  apps/zcl-ledger/device-blue-sign-test/bin/app.elf /tmp/zcl-sign-test.bin
sha256sum /tmp/zcl-sign-test.bin
```

The pinned 12,544-byte image hash is
`0fc38931f3344715090953538495c9648b3e475621853ac4c2dc7e568874590b`.
The build requires zero initialized `.data` bytes. At the Blue home screen,
install the pinned image with the owner-controlled CA. The installer limits
this app to the secp256k1 curve and `m/44'/147'/0'/0/0` in BOLOS install
metadata; those permissions are necessary for device key derivation:

```sh
zcl-blue-install /dev/hidrawN --ca-install CA_KEY_FILE /tmp/zcl-sign-test.bin
```

Open `ZCL Sign Test`, tap `SIGN TEST`, and run:

```sh
zcl-blue-sign-test --json /dev/hidrawN
```

The host returns `signature_verified:true` only after checking the ECDSA
signature over the fixed message under the returned public key. It always
reports `transaction_signed:false`. A second request requires another tap.
Remove the app at home with
`zcl-blue-install /dev/hidrawN --ca-delete-sign-test CA_KEY_FILE`.

The USB protocol uses CLA `A5`, P1/P2 zero, and empty `Lc`:

| INS | Response before `9000` |
| --- | --- |
| `01` | `ZCL`, protocol version `07`, fixed-test capability `02` |
| `20` | 33-byte compressed public key, one-byte DER length, DER signature |

Before the tap, `20` returns `6985`. Any other instruction returns `6D00`.
The app has no transaction approval interface. A future payment signer must
show the actual recipient, amount, fee, and signing path on the Blue and bind
approval to the reviewed transaction.
