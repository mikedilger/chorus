# Chorus

Chorus is a nostr relay.

It is pretty fast: [docs/PERFORMANCE.md](docs/PERFORMANCE.md).

It can work as your personal relay: [docs/PERSONAL_RELAY.md](docs/PERSONAL_RELAY.md).

To deploy chorus, read [docs/DEPLOYING.md](docs/DEPLOYING.md)

To configure chorus read [docs/CONFIG.md](docs/CONFIG.md)

To undertand the relay's behavior, read [docs/BEHAVIOR.md](docs/BEHAVIOR.md)

To understand command line tools, read [docs/TOOLS.md](docs/TOOLS.md)

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
- Chorus has extensive IP banning to protect your relay from abuse
- Chorus supports NIP-42 (AUTH), NIP-59 (GiftWrap), NIP-65 (Relay Lists) and PR 1030.
- Chorus has a moderation tool

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

## Change Log

### Version 1.4.0 (2024-05-07, 25058ef4)

- Origin header logged
- CLOSED: auth-required sent if DMs requested and not authenticated yet
- config: minimum_ban_seconds, timeout_seconds, dont_ip_block
- default for allow_scrape_if_max_seconds raised from 3600 to 7200
- default for max_subscriptions raised from 32 to 128
- timeouts no longer affect ban seconds
- Internal: switched to pocket for the backend storage
- creates lmdb subdirectory if missing
- several bugfixes: filter parsing, empty tags, event ordering, chorus_compress was fixed

### Version 1.3.0 (2024-04-10, 7883d754)

- `chorus_moderate` tool to approve events or pubkeys
- `chorus_dump_approvals` tool to view prior approvals
- `chorus_compress` to backup and rebuild your data, compressing as it goes.
- NIP-40 event expiration support
- extended NIP-11 document, with updates to supported NIPs
- Traffic bytes counted and logged on exit (or HUP)
- Logging improvements
- Data migrations. Less space consumed.
- performance improved via 8-byte alignment of events

### Version 1.2.0 (2024-03-22, a701e148)

- Config option to run as an open relay
- Config variable for scraper behavior
- More efficient scraping
- Reload config on HUP without dropping connections
- IP addresses no longer logged. They are hashed and tracked by their hash.

### Version 1.1.1 (2024-03-02, fda607a6)

- FIX some LIMIT related bugs
- FIX some indexing bugs that cuased some events that should have been returned to not be.
- Allow scrape up to limit=100, or time range of 1 hour

### Version 1.1.0 (2024-02-21, ec315d98)

- Update docs

### Version 1.0.7 (2024-02-21, 4ebe2545)

- BREAKING: Config changed to TOML format
- Logging improvements
- Error handling improvements
- Ban time improvements
- Documentation updates
- Restructured into a `bin` and a `lib`
- Tool to dump all events as JSON to stdout

### Version 1.0.6 (2024-02-21, 50995a75)

- FIX: REQ errors now properly CLOSED
- Logging improvements
- Persistent IP reputation data for adjusting ban times
- Config settings for `serve_ephmeral` and `serve_relay_lists`
- Uses 'X-Real-Ip' header if behind a proxy

### Version 1.0.5 (2024-02-20, 5e7c1c38)

- FIX: significant performance problem addressed
- Logging improvements
- EVENTs submitted that are known to be deleted are now responded to with 'blocked:'
- Longer filters now accepted

### Version 1.0.4 (2024-02-20, 9c7aa299)

- FIX: after EOSE, outbound events were not being screened properly
- FIX: shutdown issue
- NIP-11 updated
- Idle connections with no REQs now timed out at 5 seconds

### Version 1.0.3 (2024-02-20, 015d847f)

- FIX: limits were not working properly
- Update IP banning logic and timing
- Improve logging
- Allow more REQ filters (with low limits)
- Better performance when filters are more open

### Version 1.0.2 (2024-02-19, b85cd929)

- FIX: deadlock (nested transaction issue)
- Logging changes
- Documentation updated

### Version 1.0.1 (2024-02-19, 9d65d773)

- FIX: AUTH was failing due to a bad time difference comparison
- AUTH failures now include detail as to why
- documentation updated

### Version 1.0.0 (2024-02-19, 7ed36b95)

- Initial release.
- Works as a personal relay
- Supported NIPs:  1, 4, 9, 11, 42, 59, 65
- Bans IPs to prevent abuse
- Limits to 32 subscriptions by default, configurable
