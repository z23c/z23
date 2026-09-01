# ZClassic Social

Reference application for the public Z23 App ABI. It is a
permissionless signed-event social network with local, user-owned projections.

The Core owns consensus, wallet keys, sockets, storage durability, Tor, and
process lifecycle. Social receives only the capabilities declared in
`app.def`. Posts are signed and content-addressed application events gossiped
over `social.events.v1`; they are not consensus transactions. ZNAM can bind a
human name to the app's onion, clearnet endpoint, or content identity.

There is no central delete or admission authority. Each peer remains sovereign
over local storage and display policy. The required censorship-resistance
proof is network-level: if one relay refuses an otherwise valid event, honest
peers still discover it through alternate paths and converge after partitions
heal.
