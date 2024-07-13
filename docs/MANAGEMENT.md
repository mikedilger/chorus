# Chorus Management

This page is about using the online Management API.

You can also do management and moderation via command line [TOOLS.md](TOOLS.md).

## Relay Management NIP

The Relay Management API is in flux currently. It is still a pull request on the NIPs repo: [PR 1325](https://github.com/nostr-protocol/nips/pull/1325).

This document may go out of date as things are changing rapidly.

## The status of a pubkey

Users can be in one of four states: Authorized, Approved, Banned, and Default.

**Authorized**: These are the users you configured in your chorus.toml file, the users that the chorus was setup to serve, or the paying users (if you sell service). These user's events are always accepted and these users can read everything (except other user's DMs for example).  These users are statically configured in the config file and cannot be changed dynamically.

**Approved**: These are users who are not authorized, but which via moderation have been approved. Approved user's posts are publically available to anybody to read. Because they are not authorized, they can only post replies to authorized users.

**Banned**: These are users who cannot make any posts at all to the relay.

**Default**: All pubkeys not explicitly put into any of the other three categories default to this category. Because they are not authorized, they can only post replies to authorized users. Because they are not approved, these replies are only visible to authorized users and are not publicly visible (unless and until a moderator approves the specific post).
