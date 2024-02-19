# Chorus Behavior

## EVENT Write permissions and behavior

If `verify_events` is set in the configuration, chorus rejects invalid events in all cases.

Chorus accepts all events submitted by authorized users.

Chorus accepts relay list metadata (kind 10002) from anybody.

Chorus accepts all ephemeral events from anybody.

Chorus accepts all events authored by an authorized user, irrespective of who submits it. Chorus always verifies such events irrespective of the `verify_events` configuration setting.

Chorus accepts all events that tag one of the authorized users.

If you wish to change these rules, change the source code at `nostr.rs:screen_incoming_event()`

## REQ Read permissions and behavior

Chorus serves all relay list metadata (kind 10002) events queried.

Chorus serves all ephemeral events.

Chorus does not serve any DM (kind 4) or GiftWrap (kind 1059) unless the connection is AUTHed and the user matches either a tagged person or the author of the event.

Chorus serves all events to AUTHed and authorized users.

Chorus serves all events which were authored by an authorized user.

Filters which are broad are considered scrapers and are not serviced. Filters must meet one of the following criteria:

- A non-empty `id` list is set
- A non-empty `authors` list is set and a non-empty `kinds` list is set
- A non-empty `authors` list is set and at least one tag is set.
- A non-empty `kinds` list is set and at least one tag is set.

If you wish to change these rules, change the source code at `nostr.rs:screen_outgoing_event()`

## Abuse, Banning, Throttling, and the like

WebSocket frames and messages are limited to 1 MB.

Each connection has a memory buffer used for JSON deserialization that is no larger
than the WebSocket message. No more than one such buffer exists per connection, and memory
allocation is generally tightly controlled.

Every connection is IP banned for 4 seconds after disconnection, whether or not the connection
was well behaved. We don't think clients should ever reconnect immediately. If chorus is
run directly (not behind an nginx proxy), this IP banning is more efficient because it happens
prior to SSL setup.

A maximum of 32 subscriptions are allowed by default, although this is configurable with the
`max_subscriptions` configuration setting.

## NIP Support

### NIP-01 Basic protocol flow description

Chorus fully complies with NIP-01

### NIP-04 Encrypted Direct Message

Chorus fully complies with NIP-04

The chorus relay does not supply kind 4 DMs to anybody except the tagged recipient
and the author.

REQs for such disallowed events do not generate any error condition, but the events are
not supplied.

### NIP-09 Event Deletion

Chorus fully compiles with NIP-09.

Chorus both deletes matching events (matched by id and pubkey)
as well as remembering these (id,pubkey) pairs to reject such events subsequently submitted.

### NIP-11 Relay Information Document

Chorus fully complies with NIP-11.

Chorus returns a brief result without much detail.

### NIP-26 Delegated Event Signing

Chorus does not support NIP-26.

### NIP-28 Public Chat

Chorus does not support NIP-28.

### NIP-40 Expiration Timestamp

Chorus does not support NIP-40.

### NIP-42 Authentication of clients to relays

Chorus fully complies with NIP-42.

Chorus immediately sends an AUTH to every client as soon as the connection is setup.

Chorus continues to serve clients irrespective of whether they have AUTHed or not.

### NIP-45 Counting results

Chorus does not support NIP-45.

### NIP-50 Search Capability

Chorus does not support NIP-50.

### NIP-59 Gift Wrap

The chorus relay does not supply kind 1059 GiftWraps to anybody except the tagged recipient
and the author.

REQs for such disallowed events do not generate any error condition, but the events are
not supplied.

### NIP-65 Relay List Metadata

Chorus fully compiles with NIP-65.

Chorus accepts kind 10002 events from anybody, and serves such events to anybody.

### NIP-94 File Metadata

Chorus does not support NIP-94.

### NIP-96 HTTP File Storage Integration

Chorus does not support NIP-96.

