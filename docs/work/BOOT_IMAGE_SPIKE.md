<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Boot image spike: Z23 as the only program on a Linux kernel

Goal ([Ambition](../THE_Z23_WAY.md#ambition)): a machine that boots straight
into Z23 and nothing else, built so two builds give the same hash. This spike
tried the first step in a VM on 2026-11-26. It is a measurement, not a product.

## What was built

An initramfs of about 21 MB: a static busybox, the Z23 binary, and the three
libraries it needs (libc, libm, the loader), plus a ten-line init script.
Kernel: the host's own Ubuntu 6.8.0-139 generic kernel, booted with QEMU and
KVM, no disk. The Z23 binary was a development build of a stale checkout
(version string "source d09b4cb79b46"), so treat every number as a floor for
what current main can do, not a measurement of it.

## What happened

| Step | Result |
|---|---|
| Boot, run `z23 --version`, power off | worked; 0.63 s from kernel start to power off |
| NIC | the kernel has virtio-net built in; DHCP lease from QEMU in under a second |
| Same image built twice, a second apart | byte-identical (same sha256) with sorted names, fixed mtimes, owner 0, `gzip -n` |
| Node start as the only program, `-connect` to our own public node | RPC up after about 45 to 60 s; learned network tip 3332290 from the peer |
| Sync | **no progress**: H* stayed 0 for the 390 s watched (the stopwatch harness passed in 333 to 354 s on 11-16 with a lane build) |

The identical-hash result is the same inputs on one host. It does not yet pin
the inputs (the binary and the libraries came from this host).

## Not known yet

- Why H* stayed 0. Candidates, none tested: the old binary lacks the fast
  path; one peer only; no node restarts (the harness restarts the node between
  phases and passes after four boots); tmpfs datadir; VM overhead. Run the
  stopwatch recipe in `docs/node/coldstart-remote-peer-proof.md` inside the
  image with a current release binary and compare.
- Real hardware (Wi-Fi, USB, graphics): untested. The VM has one virtual NIC.
- A kernel and libc that we pin and build ourselves.

## Next steps, smallest first

1. Rebuild with a current release binary and repeat the sync with the same
   four-boot sequence the stopwatch uses; record the number.
2. Pin the inputs: the Z23 release binary by hash, a static libc build, the
   kernel by hash; show two hosts get the same image hash.
3. Boot the same initramfs on a spare physical machine from a USB stick.
4. Replace busybox init with a small C23 init that starts Z23 and restarts it.

## Recipe

```
root/{bin,dev,proc,sys,lib64,lib/x86_64-linux-gnu,tmp,data}
cp busybox z23 -> root/bin ; libc libm -> root/lib/x86_64-linux-gnu
loader -> root/lib64 ; init: mount proc sys dev, dhcp, mount tmpfs /data,
  z23 -datadir=/data -listen=0 -nolegacyimport -connect=PEER &
find . | LC_ALL=C sort | cpio -o -H newc --reproducible --owner=0:0 | gzip -9n
qemu-system-x86_64 -enable-kvm -cpu host -m 4G -nographic \
  -kernel vmlinuz -initrd initramfs.gz -append "console=ttyS0 panic=-1" \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0
```
