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
| Sync, first try (2 GB in-memory data disk, older binary) | stopped: the disk filled at height 1302; that was the test setup, not the node |
| Sync, second try (30 GB disk file, development build of 11-26, source f247c0c8af25, 2 vCPUs, 4 GB RAM) | **reached the network tip about 435 s after kernel start** (H* 3315897 at 375 s, 3332314 at 435 s against tip 3332311), then followed it; one boot, no outside restarts |

The identical-hash result is the same inputs on one host. It does not yet pin
the inputs (the binary and the libraries came from this host).

## Not known yet

- How repeatable the 435 s is. It is one run, on a busy host (load average
  about 20), with one peer that is our own node, a development build and a
  sparse disk file. Run it three times on a quiet host before quoting it.
- Why the first try showed H* at 0 for 390 s: that run's 2 GB in-memory data
  disk filled (the node logged "database or disk is full"), so it says nothing
  about the node.
- Real hardware (Wi-Fi, USB, graphics): untested. The VM has one virtual NIC.
- A kernel and libc that we pin and build ourselves.

## Next steps, smallest first

1. Repeat the sync three times on a quiet host with a release binary and
   record the spread.
2. Pin the inputs: the Z23 release binary by hash, a static libc build, the
   kernel by hash; show two hosts get the same image hash.
3. Boot the same initramfs on a spare physical machine from a USB stick.
4. Replace busybox init with a small C23 init that starts Z23 and restarts it.

## Recipe

```
root/{bin,dev,proc,sys,lib64,lib/x86_64-linux-gnu,tmp,data}
cp busybox z23 -> root/bin ; libc libm -> root/lib/x86_64-linux-gnu
loader -> root/lib64 ; a development build also needs libstdc++ and libgcc_s
init: mount proc sys dev, dhcp, mount the data disk (ext4, 30 GB sparse) on /data,
  z23 -datadir=/data -listen=0 -nolegacyimport -connect=PEER &
find . | LC_ALL=C sort | cpio -o -H newc --reproducible --owner=0:0 | gzip -9n
qemu-system-x86_64 -enable-kvm -cpu host -m 4G -nographic \
  -kernel vmlinuz -initrd initramfs.gz -append "console=ttyS0 panic=-1" \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
  -drive file=data.img,format=raw,if=virtio,cache=unsafe
```
