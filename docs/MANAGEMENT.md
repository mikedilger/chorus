# Chorus Management

This page is about using the online Management API or command line [TOOLS.md](TOOLS.md)
to manage users and moderate events.

## Managing users

To list users:  `chorus_cmd <configtoml> dump_users`

To add a user:  `chorus_cmd <configtoml> add_user <pubkeyhex> 0`

To add a moderator:  `chorus_cmd <configtoml> add_user <pubkeyhex> 1`

To remove moderator flag, just add the user again with 0.

To remove a user: `chorus_cmd <configtoml> rm_user <pubkeyhex>`

## Managing events

To cycle through all events needing moderation, and address each one, use `chorus_moderate <configtoml>`

To remove an event by id: `chorus_cmd <configtoml> delete_by_id <idhex>`

To remove multiple events by pubkey: `chorus_cmd <configtoml> delete_by_pubkey <pubkeyhex>`

## Relay Management NIP

The Relay Management API is in flux currently. It is still a pull request on the NIPs repo: [PR 1325](https://github.com/nostr-protocol/nips/pull/1325).

This document may go out of date as things are changing rapidly.

## The status of a pubkey (user)

Users can be in one of four moderation states: Authorized, Approved, Banned, and Default.

**Authorized**: These are the users you have added as authorized (whether or not they are a moderator). These user's events are always accepted and these users can read everything (except other user's DMs for example).

**Approved**: These are users who are not authorized, but which via moderation have been approved. Approved user's posts are publically available to anybody to read. Because they are not authorized, they can only post replies to authorized users.

**Banned**: These are users who cannot make any posts at all to the relay.

**Default**: All pubkeys not explicitly put into any of the other three categories default to this category. Because they are not authorized, they can only post replies to authorized users. Because they are not approved, these replies are only visible to authorized users and are not publicly visible (unless and until a moderator approves the specific post).
