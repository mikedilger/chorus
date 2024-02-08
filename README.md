# Chorus

Chorus is a nostr relay in development

Development is early and rapid. This is NOT ready to use by any stretch of the imagination.

## Plans

High performance due to:

- Rust language
- Asynchronous multithreading
- Memory mapped storage
- Event memory map is almost lock-free (limited to one writer at a time)
- Direct indexing: indices yield the memory offset of the event, not an ID that requires another lookup
- LMDB used for indexes
- In-place zero-copy event field access (does not require deserialization)
- Custom JSON parsing without memory allocation

Simple to deploy due to:

- Being the webserver and the relay for standalone deployment
- TLS optional, to support both standalone and behind-proxy deployment
- Just a single configuration file
- systemd and nginx setups contributed

Flexible nostr usage:

- Can use as personal relay, inbox, DM inbox, etc, with flexible rules around access

## Not Planned (yet)

Bitcoin/Lightning integration:

- I don't plan to add this any time soon.
- You won't be able to charge for service.
