# z23-userns AppArmor profile

On Ubuntu 23.10 and later the kernel sets
`kernel.apparmor_restrict_unprivileged_userns=1`. Processes can still call
`unshare(CLONE_NEWUSER)`, but writing `/proc/self/uid_map` fails with EPERM, so
the terminal hub cannot build the user+PID namespace its worker needs and
refuses every session with `TERMINAL_PIDNS_UNAVAILABLE`. The refusal is
deliberate: there is no unconfined fallback.

`z23-userns` grants `userns,` to the installed binary
(`~/.local/lib/z23/<sha256>/z23`, matched by an `@{HOME}` glob) and nothing
else. It is not installed automatically. The one root command:

    sudo install -m 0644 platform/packaging/linux/apparmor/z23-userns /etc/apparmor.d/z23-userns && sudo apparmor_parser -r /etc/apparmor.d/z23-userns

The profile persists across reboots. Remove it with
`sudo apparmor_parser -R /etc/apparmor.d/z23-userns && sudo rm /etc/apparmor.d/z23-userns`.
The alternative, `sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`,
lifts the restriction for every program on the host and is not recommended.
