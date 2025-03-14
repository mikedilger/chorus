# Chorus

Chorus is a nostr relay.

It is pretty fast: [docs/PERFORMANCE.md](docs/PERFORMANCE.md).

It can work as your personal relay (or as an open relay): [docs/PERSONAL_RELAY.md](docs/PERSONAL_RELAY.md)

It can serve as a blossom server.

To deploy chorus, read [docs/DEPLOYING.md](docs/DEPLOYING.md)

To configure chorus read [docs/CONFIG.md](docs/CONFIG.md)

To undertand the relay's behavior, read [docs/BEHAVIOR.md](docs/BEHAVIOR.md)

To understand command line tools, read [docs/TOOLS.md](docs/TOOLS.md)

To understand the management API, read [docs/MANAGEMENT.md](docs/MANAGEMENT.md)

Chorus does not have any provisions for charging users.

Chorus does not have any provisions for synchronizing events with other relays outside of the nostr protocol.

## Alternatives

### strfry

[strfry](https://github.com/hoytech/strfry) is a more mature relay that offers additional features including:

- Synchronizing events with other relays efficiently (negentropy)
- Zero-downtime restarts
- Websocket permessage-deflate
- Plugins for event sifting

However:

- Chorus is probably faster (more efficient)
- Chorus has personal relay rules by default
- Chorus has extensive IP banning and rate limiting to protect your relay from abuse
- Chorus supports NIP-42 (AUTH), NIP-59 (GiftWrap), NIP-65 (Relay Lists) and PR 1030 and PR 1325.
- Chorus has a moderation cmd line tool and a moderation API (PR 1325)
- Chorus can act as a blossom server

### nostream

[nostream](https://github.com/Cameri/nostream)

### nostr-rs-relay

[nostr-rs-relay](https://git.sr.ht/~gheartsfield/nostr-rs-relay)

### khatru

[khatru](https://github.com/fiatjaf/khatru)

## Git branches

Use the branch `latest`.

Do not run off of the `master` branch. Master is updated with breaking changes that are
not only unstable, but which may require you to update your configuration. I will not
announce upgrade instructions until release.
